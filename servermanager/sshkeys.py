"""Servermanager's own SSH key pair and private key parsing helpers."""
from __future__ import annotations

import io
import os
import socket
from pathlib import Path

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import get_config


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def generate_ed25519(comment: str) -> tuple[str, str]:
    """Return (openssh private key PEM, public key line)."""
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                        serialization.PublicFormat.OpenSSH).decode()
    return priv, f"{pub} {comment}"


def ensure_keypair(force: bool = False) -> str:
    cfg = get_config()
    path = cfg.ssh_key_path
    if force or not path.exists():
        priv, pub = generate_ed25519(f"servermanager@{socket.gethostname()}")
        _write_private(path, priv.encode())
        Path(str(path) + ".pub").write_text(pub + "\n")
    return public_key()


def public_key() -> str:
    p = Path(str(get_config().ssh_key_path) + ".pub")
    return p.read_text().strip() if p.exists() else ""


def default_private_key() -> paramiko.PKey | None:
    path = get_config().ssh_key_path
    if not path.exists():
        return None
    return load_private_key(path.read_text())


def load_private_key(text: str, passphrase: str | None = None) -> paramiko.PKey:
    text = text.strip() + "\n"
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except paramiko.PasswordRequiredException as exc:
            raise ValueError("Der private Schlüssel ist verschlüsselt - Passphrase angeben.") from exc
        except Exception as exc:  # noqa: BLE001 - try next key type
            errors.append(f"{cls.__name__}: {exc}")
    raise ValueError("Privater Schlüssel konnte nicht gelesen werden (unterstützt: ed25519, ecdsa, rsa).")


def public_from_private(text: str, passphrase: str | None = None) -> str:
    key = load_private_key(text, passphrase)
    return f"{key.get_name()} {key.get_base64()}"
