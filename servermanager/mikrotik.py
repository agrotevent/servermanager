"""Minimal MikroTik RouterOS v7 REST API client."""
from __future__ import annotations

import logging
from typing import Any, Optional

import requests

from . import tlspin

log = logging.getLogger(__name__)


class MikroTikError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class MikroTik:
    def __init__(self, url: str, user: str, password: str, verify_tls: bool = False, timeout: int = 15,
                 fingerprint: str = ""):
        url = (url or "").strip().rstrip("/")
        if not url:
            raise MikroTikError("Keine MikroTik-API-URL konfiguriert")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if url.endswith("/rest"):
            url = url[:-5]
        self.base = url + "/rest"
        self.session = requests.Session()
        # RouterOS expects UTF-8 (requests would encode str credentials as latin-1)
        self.user = user or ""
        self.session.auth = ((user or "").encode("utf-8"), (password or "").encode("utf-8"))
        self.session.verify = verify_tls
        self.session.trust_env = False  # never send credentials through a proxy from the environment
        self.session.headers["Content-Type"] = "application/json"
        self.timeout = timeout
        if fingerprint and url.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise MikroTikError(str(exc)) from exc
            self.session.verify = False
            self.session.mount(url + "/", adapter)
        elif not verify_tls and url.startswith("https://"):
            # never send the router login to an unverified TLS endpoint
            raise MikroTikError("MikroTik: Zertifikat weder gepinnt noch über die System-CAs geprüft – bitte den "
                                "Fingerabdruck hinterlegen („Abrufen“)")

    @classmethod
    def from_settings(cls, db) -> "MikroTik":
        from . import settings
        return cls(settings.get(db, "wg.mikrotik_url"), settings.get(db, "wg.mikrotik_user"),
                   settings.get(db, "wg.mikrotik_password"), bool(settings.get(db, "wg.mikrotik_verify_tls")),
                   fingerprint=settings.get(db, "wg.mikrotik_fingerprint") or "")

    # ------------------------------------------------------------------
    def _req(self, method: str, path: str, data: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        url = f"{self.base}/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, json=data, params=params, timeout=self.timeout,
                                     allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise MikroTikError(f"TLS-Fehler bei {self.base} (Zertifikat?): {exc}") from exc
        except requests.RequestException as exc:
            raise MikroTikError(f"MikroTik nicht erreichbar ({self.base}): {exc}") from exc
        if r.status_code == 401:
            raise MikroTikError(f"MikroTik: Anmeldung als „{self.user}“ fehlgeschlagen (Benutzer/Passwort/Rechte "
                                "prüfen)", 401)
        if r.status_code >= 400:
            try:
                j = r.json()
                msg = f"{j.get('message', '')}: {j.get('detail', '')}"
            except ValueError:
                msg = r.text[:300]
            raise MikroTikError(f"MikroTik-Fehler {r.status_code} bei {method} {path}: {msg}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError as exc:
            raise MikroTikError("Ungültige Antwort der MikroTik-API") from exc

    def get(self, path: str, **filters) -> list[dict]:
        res = self._req("GET", path, params=filters or None)
        if isinstance(res, dict):
            return [res]
        return res or []

    def create(self, path: str, data: dict) -> dict:
        return self._req("PUT", path, data=data) or {}

    def patch(self, path: str, item_id: str, data: dict) -> dict:
        return self._req("PATCH", f"{path}/{item_id}", data=data) or {}

    def delete(self, path: str, item_id: str) -> None:
        self._req("DELETE", f"{path}/{item_id}")

    def command(self, path: str, data: Optional[dict] = None, timeout: Optional[int] = None) -> Any:
        """Run a console command (POST /rest/<menu>/<command>), e.g. ip/dhcp-server/lease/make-static."""
        if timeout:
            old, self.timeout = self.timeout, timeout
            try:
                return self._req("POST", path, data=data or {})
            finally:
                self.timeout = old
        return self._req("POST", path, data=data or {})

    # ------------------------------------------------------------------
    def identity(self) -> str:
        res = self._req("GET", "system/identity")
        return (res or {}).get("name", "") if isinstance(res, dict) else ""

    def resource(self) -> dict:
        res = self._req("GET", "system/resource")
        return res if isinstance(res, dict) else {}

    def wg_interface(self, name: str) -> Optional[dict]:
        items = self.get("interface/wireguard", name=name)
        return items[0] if items else None

    def wg_peers(self, interface: str) -> list[dict]:
        return self.get("interface/wireguard/peers", interface=interface)

    def add_peer(self, interface: str, public_key: str, allowed: list[str], comment: str) -> str:
        res = self.create("interface/wireguard/peers", {
            "interface": interface, "public-key": public_key,
            "allowed-address": ",".join(allowed), "comment": comment,
        })
        return res.get(".id", "")

    def set_peer_allowed(self, peer_id: str, allowed: list[str]) -> None:
        self.patch("interface/wireguard/peers", peer_id, {"allowed-address": ",".join(allowed)})

    def add_route(self, dst: str, gateway: str, comment: str) -> str:
        res = self.create("ip/route", {"dst-address": dst, "gateway": gateway, "comment": comment})
        return res.get(".id", "")

    def add_address_list(self, list_name: str, address: str, comment: str) -> str:
        res = self.create("ip/firewall/address-list", {"list": list_name, "address": address, "comment": comment})
        return res.get(".id", "")

    def delete_checked(self, path: str, item_id: str, comment_prefix: str) -> bool:
        """Delete an item only if its comment still carries our marker (ids can be reused)."""
        if not item_id:
            return False
        try:
            items = self.get(f"{path}/{item_id}")
        except MikroTikError:
            return False
        if not items or not str(items[0].get("comment", "")).startswith(comment_prefix):
            return False
        self.delete(path, item_id)
        return True

    def delete_by_comment(self, path: str, comment_prefix: str) -> int:
        n = 0
        for item in self.get(path):
            if str(item.get("comment", "")).startswith(comment_prefix) and item.get(".id"):
                self.delete(path, item[".id"])
                n += 1
        return n
