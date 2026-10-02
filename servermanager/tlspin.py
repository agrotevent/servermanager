"""TLS certificate pinning helpers (self-signed certificates of Proxmox, RouterOS, ...).

Instead of disabling certificate checks, the SHA-256 fingerprint of the
server certificate is pinned (fetched once and confirmed by an administrator).
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from typing import Optional

from requests.adapters import HTTPAdapter

FINGERPRINT_RE = re.compile(r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")


class PinError(ValueError):
    pass


def normalize_fingerprint(fp: str) -> str:
    fp = (fp or "").strip().upper().replace(" ", "")
    if fp.startswith("SHA256"):
        fp = fp.split("=", 1)[-1]
    if ":" not in fp and len(fp) == 64:
        fp = ":".join(fp[i:i + 2] for i in range(0, 64, 2))
    if not FINGERPRINT_RE.match(fp):
        raise PinError("Ungültiger SHA-256-Fingerabdruck (Format AA:BB:…, 32 Bytes)")
    return fp


def tls_hint(exc: Exception, port: Optional[int] = None) -> str:
    """Readable explanation for typical TLS handshake failures (empty if none applies)."""
    text = str(exc).lower()
    if "wrong_version_number" in text or "wrong version number" in text or "record layer failure" in text \
            or "packet length too long" in text or "http request" in text:
        where = f"Port {port}" if port else "Dieser Port"
        return (f"{where} spricht kein TLS, sondern unverschlüsseltes http. Entweder den https-Port eintragen "
                "(z. B. authentik 9443, Proxmox 8006, ISPConfig 8080, sonst 443) oder die Adresse ausdrücklich "
                "mit http:// angeben (nur im internen Netz).")
    if "certificate verify failed" in text or "fingerprint" in text:
        return ("Das Zertifikat passt nicht zum hinterlegten Fingerabdruck bzw. ist nicht vertrauenswürdig – "
                "Fingerabdruck neu abrufen und vergleichen.")
    return ""


def tls_message(where: str, exc: Exception) -> str:
    """Error text for API clients: the explanation when known, otherwise the raw error."""
    from urllib.parse import urlsplit
    try:
        port = urlsplit(where).port
    except ValueError:
        port = None
    hint = tls_hint(exc, port)
    return f"TLS-Fehler bei {where}: {hint}" if hint else f"TLS-Fehler bei {where}: {exc}"


def fetch_fingerprint(host: str, port: int, timeout: int = 10) -> str:
    """SHA-256 fingerprint of the certificate the server presents (not validated)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        hint = tls_hint(exc, port)
        raise PinError(f"{host}:{port}: {hint}" if hint else f"{host}:{port} nicht erreichbar: {exc}") from exc
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, 64, 2))


class PinnedAdapter(HTTPAdapter):
    """Accept exactly the certificate with the given SHA-256 fingerprint."""

    def __init__(self, fingerprint: str, **kwargs):
        self._fingerprint = normalize_fingerprint(fingerprint)
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self._fingerprint
        kwargs["cert_reqs"] = "CERT_NONE"
        return super().init_poolmanager(*args, **kwargs)
