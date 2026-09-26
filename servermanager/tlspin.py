"""TLS certificate pinning helpers (self-signed certificates of Proxmox, RouterOS, ...).

Instead of disabling certificate checks, the SHA-256 fingerprint of the
server certificate is pinned (fetched once and confirmed by an administrator).
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl

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
        raise PinError(f"{host}:{port} nicht erreichbar: {exc}") from exc
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
