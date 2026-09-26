"""Cryptographic helpers: secret key, field encryption, passwords, TOTP, tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import get_config

_ph = PasswordHasher()
_master_key: bytes | None = None
_fernet: Fernet | None = None

MIN_PASSWORD_LENGTH = 10


# --------------------------------------------------------------------------
# Master key
# --------------------------------------------------------------------------
def ensure_secret_key(path: str | None = None) -> bytes:
    """Load the master key; create it (0600) if it does not exist yet."""
    path = path or get_config().secret_key_file
    p = Path(path)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key + b"\n")
    raw = p.read_bytes().strip()
    key = base64.urlsafe_b64decode(raw)
    if len(key) != 32:
        raise RuntimeError(f"invalid secret key in {path}")
    return key


def master_key() -> bytes:
    global _master_key
    if _master_key is None:
        _master_key = ensure_secret_key()
    return _master_key


def reset_key_cache() -> None:
    global _master_key, _fernet
    _master_key = None
    _fernet = None


def derive_key(purpose: str, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=f"servermanager:{purpose}".encode()).derive(master_key())


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(base64.urlsafe_b64encode(derive_key("fernet")))
    return _fernet


def encrypt(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return _get_fernet().encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str:
    if not value:
        return ""
    try:
        return _get_fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Entschlüsselung fehlgeschlagen - falscher Schlüssel (secret.key)?") from exc


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"Das Passwort muss mindestens {MIN_PASSWORD_LENGTH} Zeichen lang sein.")
    classes = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                   any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
    if classes < 3:
        problems.append("Das Passwort muss mindestens drei Zeichenarten enthalten "
                        "(Klein-, Großbuchstaben, Ziffern, Sonderzeichen).")
    return problems


def random_password(length: int = 20) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if not password_problems(pw):
            return pw


# --------------------------------------------------------------------------
# TOTP
# --------------------------------------------------------------------------
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, issuer: str = "Servermanager") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------
def new_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def const_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def generate_password(length: int = 16) -> str:
    """Random password with upper/lower case letters, digits and a symbol (for app accounts)."""
    import string
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length - 2)) + secrets.choice("-_.!+") + \
            secrets.choice(string.digits)
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
            return pw
