"""Client for the authentik API (/api/v3, Bearer token).

The API is used internally (``api_url``); the OIDC endpoints handed to the
applications use the public URL (reached through Pangolin), because the
browsers of the users have to reach the login pages.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import quote, urlsplit

import requests

from . import tlspin

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,49}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,150}$")
SCOPES = ("goauthentik.io/providers/oauth2/scope-openid", "goauthentik.io/providers/oauth2/scope-email",
          "goauthentik.io/providers/oauth2/scope-profile")


class AuthentikError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def base_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username:
        raise AuthentikError("Ungültige Adresse")
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}"


class Authentik:
    def __init__(self, api_url: str, token: str, public_url: str = "", fingerprint: str = "",
                 verify_ca: bool = True, timeout: int = 20):
        self.base = base_url(api_url)
        self.public = base_url(public_url or api_url)
        if not token:
            raise AuthentikError("Kein API-Token hinterlegt")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
        if fingerprint and self.base.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise AuthentikError(str(exc)) from exc
            self.session.verify = False
            self.session.mount(self.base + "/", adapter)
        else:
            self.session.verify = verify_ca

    def request(self, method: str, path: str, body: Any = None, params: Optional[dict] = None) -> Any:
        url = f"{self.base}/api/v3/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, json=body, params=params, timeout=self.timeout,
                                     allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise AuthentikError(tlspin.tls_message(self.base, exc)) from exc
        except requests.RequestException as exc:
            raise AuthentikError(f"authentik nicht erreichbar ({self.base}): {exc}") from exc
        if r.status_code in (401, 403):
            raise AuthentikError("authentik: Zugriff verweigert (API-Token/Rechte prüfen)", r.status_code)
        if r.status_code >= 400:
            try:
                detail = r.json()
            except ValueError:
                detail = r.text[:300]
            raise AuthentikError(f"authentik-Fehler {r.status_code} bei {method} {path}: {detail}", r.status_code)
        if r.status_code == 204 or not r.content:
            return None
        return r.json()

    def _all(self, path: str, params: Optional[dict] = None) -> list[dict]:
        out, page = [], 1
        while True:
            data = self.request("GET", path, params={**(params or {}), "page": page, "page_size": 100}) or {}
            out.extend(data.get("results", []))
            if not (data.get("pagination") or {}).get("next"):
                return out
            page += 1

    # ------------------------------------------------------------------ OIDC (login to the servermanager)
    def _oauth(self, method: str, path: str, **kw) -> dict:
        """OAuth endpoints over the internal (pinned) address – never with the API token."""
        url = f"{self.base}/application/o/{path}"
        headers = {"Authorization": kw.pop("bearer", None), "Accept": "application/json"}
        try:
            r = self.session.request(method, url, headers=headers, timeout=self.timeout, allow_redirects=False,
                                     **kw)
        except requests.exceptions.SSLError as exc:
            raise AuthentikError(tlspin.tls_message(self.base, exc)) from exc
        except requests.RequestException as exc:
            raise AuthentikError(f"authentik nicht erreichbar ({self.base}): {exc}") from exc
        try:
            j = r.json()
        except ValueError:
            j = {}
        if r.status_code >= 400 or not isinstance(j, dict):
            msg = (j.get("error_description") or j.get("error")) if isinstance(j, dict) else ""
            raise AuthentikError(f"authentik: Anmeldung abgelehnt ({msg or f'HTTP {r.status_code}'})", r.status_code)
        return j

    def oidc_token(self, code: str, redirect_uri: str, client_id: str, client_secret: str, verifier: str) -> dict:
        return self._oauth("POST", "token/", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": client_id, "client_secret": client_secret, "code_verifier": verifier})

    def oidc_userinfo(self, access_token: str) -> dict:
        return self._oauth("GET", "userinfo/", bearer=f"Bearer {access_token}")

    # ------------------------------------------------------------------ info
    def version(self) -> str:
        return (self.request("GET", "admin/version/") or {}).get("version_current", "")

    def applications(self) -> list[dict]:
        return self._all("core/applications/")

    # ------------------------------------------------------------------ users
    def users(self) -> list[dict]:
        return [u for u in self._all("core/users/") if u.get("type", "internal") in ("internal", "external")]

    def groups(self) -> list[dict]:
        return self._all("core/groups/")

    def create_user(self, username: str, name: str, email: str, password: str = "",
                    groups: Optional[list[str]] = None, active: bool = True) -> dict:
        if not USERNAME_RE.match(username or ""):
            raise AuthentikError("Ungültiger Benutzername")
        user = self.request("POST", "core/users/", {"username": username, "name": name or username,
                                                    "email": email, "is_active": bool(active), "path": "users"})
        if password:
            self.request("POST", f"core/users/{int(user['pk'])}/set_password/", {"password": password})
        for gpk in groups or []:
            self.request("POST", f"core/groups/{quote(str(gpk), safe='')}/add_user/", {"pk": user["pk"]})
        return user

    def create_group(self, name: str) -> dict:
        name = (name or "").strip()
        if not name or len(name) > 150:
            raise AuthentikError("Ungültiger Gruppenname")
        return self.request("POST", "core/groups/", {"name": name, "is_superuser": False, "users": []}) or {}

    def add_group_members(self, group_pk: str, user_pks: set[int]) -> int:
        """Adds users to a group (one request); returns how many were not members yet."""
        path = f"core/groups/{quote(str(group_pk), safe='')}/"
        current = {int(x) for x in (self.request("GET", path, params={"include_users": "false"}) or {})
                   .get("users") or []}
        new = {int(x) for x in user_pks} - current
        if new:
            self.request("PATCH", path, {"users": sorted(current | new)})
        return len(new)

    def user(self, pk: int) -> dict:
        return self.request("GET", f"core/users/{int(pk)}/") or {}

    def is_admin_user(self, pk: int) -> bool:
        """Superuser directly or through one of its groups."""
        u = self.user(pk)
        return bool(u.get("is_superuser")) or any(g.get("is_superuser") for g in (u.get("groups_obj") or []))

    def set_active(self, pk: int, active: bool) -> None:
        self.request("PATCH", f"core/users/{int(pk)}/", {"is_active": bool(active)})

    def set_password(self, pk: int, password: str) -> None:
        self.request("POST", f"core/users/{int(pk)}/set_password/", {"password": password})

    def delete_user(self, pk: int) -> None:
        self.request("DELETE", f"core/users/{int(pk)}/")

    # ------------------------------------------------------------------ OIDC applications
    def _flow(self, designation: str, preferred: str) -> Optional[str]:
        flows = self._all("flows/instances/", {"designation": designation})
        f = next((x for x in flows if x.get("slug") == preferred), None) or (flows[0] if flows else None)
        return f.get("pk") if f else None

    def _scope_mappings(self) -> list[str]:
        for path in ("propertymappings/provider/scope/", "propertymappings/scope/"):
            try:
                maps = self._all(path)
            except AuthentikError as exc:
                if exc.status == 404:
                    continue
                raise
            pks = [m["pk"] for m in maps if m.get("managed") in SCOPES]
            if pks:
                return pks
        return []

    def _signing_key(self) -> Optional[str]:
        keys = self._all("crypto/certificatekeypairs/", {"has_key": "true"})
        k = next((x for x in keys if x.get("name") == "authentik Self-signed Certificate"), None) or \
            (keys[0] if keys else None)
        return k.get("pk") if k else None

    def create_oidc_app(self, name: str, slug: str, redirect_uris: list[str], launch_url: str,
                        client_type: str = "confidential") -> dict:
        """OAuth2/OIDC provider + application. Returns client_id, client_secret, discovery URL, provider pk.

        ``client_type`` "public" for applications that cannot keep a secret and use PKCE (Zammad)."""
        if client_type not in ("confidential", "public"):
            raise AuthentikError("Ungültiger Client-Typ")
        if not SLUG_RE.match(slug):
            raise AuthentikError("Ungültiger Slug")
        existing = [a for a in self.applications() if a.get("slug") == slug]
        if existing:
            raise AuthentikError(f"In authentik gibt es bereits eine Anwendung „{slug}“")
        auth_flow = self._flow("authorization", "default-provider-authorization-implicit-consent")
        if not auth_flow:
            raise AuthentikError("Kein Autorisierungs-Flow gefunden")
        body = {"name": name, "authorization_flow": auth_flow, "client_type": client_type,
                "redirect_uris": [{"matching_mode": "strict", "url": u} for u in redirect_uris],
                "property_mappings": self._scope_mappings(), "sub_mode": "user_username",
                "include_claims_in_id_token": True}
        inv = self._flow("invalidation", "default-provider-invalidation-flow")
        if inv:
            body["invalidation_flow"] = inv
        key = self._signing_key()
        if key:
            body["signing_key"] = key
        try:
            provider = self.request("POST", "providers/oauth2/", body)
        except AuthentikError as exc:
            if exc.status != 400:
                raise
            # authentik < 2024.10: redirect URIs as newline separated string, no invalidation flow
            body["redirect_uris"] = "\n".join(redirect_uris)
            body.pop("invalidation_flow", None)
            provider = self.request("POST", "providers/oauth2/", body)
        try:
            self.request("POST", "core/applications/", {"name": name, "slug": slug, "provider": provider["pk"],
                                                        "meta_launch_url": launch_url})
        except AuthentikError:
            self.request("DELETE", f"providers/oauth2/{int(provider['pk'])}/")
            raise
        return {"provider_pk": provider["pk"], "client_id": provider.get("client_id", ""),
                "client_secret": provider.get("client_secret", ""), **self.endpoints(slug)}

    def endpoints(self, slug: str) -> dict:
        p = self.public
        return {"discovery": f"{p}/application/o/{slug}/.well-known/openid-configuration",
                "issuer": f"{p}/application/o/{slug}/", "authorize": f"{p}/application/o/authorize/",
                "token": f"{p}/application/o/token/", "userinfo": f"{p}/application/o/userinfo/",
                "logout": f"{p}/application/o/{slug}/end-session/"}

    def delete_oidc_app(self, slug: str, provider_pk: Optional[int]) -> None:
        try:
            self.request("DELETE", f"core/applications/{quote(slug, safe='')}/")
        except AuthentikError as exc:
            if exc.status != 404:
                raise
        if provider_pk:
            try:
                self.request("DELETE", f"providers/oauth2/{int(provider_pk)}/")
            except AuthentikError as exc:
                if exc.status != 404:
                    raise
