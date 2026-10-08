"""Link existing accounts: authentik ↔ Nextcloud ↔ Mailcow.

The applications find the account of a person who logs in through authentik like this:

- Nextcloud (app user_oidc, set up by the servermanager): the authentik user name is the Nextcloud user ID; an
  existing account with this ID is taken over (soft auto provisioning) with its files, shares and groups.
- Mailcow: the e-mail address of the authentik user is the mailbox; the mailbox must use the identity provider
  as its authentication source ("authsource"), otherwise Mailcow refuses the login.

``plan`` puts the accounts of the three systems side by side per person and lists what is missing for a working
login with the existing account and its rights (groups). ``apply`` carries out the chosen fixes; it recomputes
the plan itself, so the browser only selects rows and kinds of fixes, never values.
"""
from __future__ import annotations

import re
from typing import Optional

from . import security
from .authentik import USERNAME_RE, Authentik, AuthentikError
from .mailcow import MailcowError
from .nc_import import ADMIN_GROUP

# kinds of fixes, in the order they are carried out
FIXES = {
    "create": "authentik-Benutzer anlegen",
    "rename": "authentik-Benutzername = Nextcloud-ID",
    "email": "E-Mail in authentik = Postfach",
    "groups": "Nextcloud-Gruppen in authentik",
    "authsource": "Postfach auf authentik umstellen",
}
MAX_ROWS = 300   # per run, keeps one request within the proxy timeout


def _low(v) -> str:
    return str(v or "").strip().lower()


def mailbox_authsource(mb: dict) -> str:
    return str(mb.get("authsource") or "mailcow")


def plan(ak_users: list[dict], ak_groups: list[dict], nc_users: Optional[list[dict]] = None,
         mailboxes: Optional[list[dict]] = None, idp_authsource: str = "", is_admin: bool = False) -> dict:
    """One row per person.

    ``nc_users``: normalized (nc_import.normalize_users), ``mailboxes``: Mailcow ``get/mailbox/all``,
    ``idp_authsource``: type of the identity provider configured in the Mailcow ("generic-oidc", "keycloak" or
    "" if none). ``is_admin``: administrator of the servermanager; only they may touch authentik superusers and
    Nextcloud administrators (taking over such an account means taking over the system).
    """
    nc_users = nc_users or []
    mailboxes = mailboxes or []
    ak_by_name = {_low(u.get("username")): u for u in ak_users}
    ak_by_mail: dict[str, list[dict]] = {}
    for u in ak_users:
        if _low(u.get("email")):
            ak_by_mail.setdefault(_low(u.get("email")), []).append(u)
    groups_of: dict = {}          # authentik user pk -> names (lower case) of its groups
    superuser_of: set = set()     # user pks that are superusers through a group
    for grp in ak_groups:
        for pk in grp.get("users") or []:
            groups_of.setdefault(pk, set()).add(_low(grp.get("name")))
            if grp.get("is_superuser"):
                superuser_of.add(pk)
    ak_group_names = {_low(x.get("name")): x for x in ak_groups}
    mb_by_addr = {_low(m.get("username")): m for m in mailboxes}

    rows: list[dict] = []
    used_ak: set = set()
    used_mb: set[str] = set()

    def row_for(ak: Optional[dict]) -> dict:
        return {"ak": ak, "nc": None, "nc_how": "", "mb": None, "mb_how": "", "fixes": [], "notes": []}

    by_ak_pk: dict = {}
    # Nextcloud accounts: by user name, otherwise by e-mail address
    for nc in nc_users:
        ak = ak_by_name.get(_low(nc["uid"]))
        how = "username" if ak else ""
        if ak is None and _low(nc["email"]):
            cands = [u for u in ak_by_mail.get(_low(nc["email"]), []) if u.get("pk") not in used_ak]
            if len(cands) == 1:
                ak, how = cands[0], "email"
        if ak is not None and ak.get("pk") in used_ak:
            ak, how = None, ""
        row = row_for(ak)
        row.update(nc=nc, nc_how=how)
        if ak is not None:
            used_ak.add(ak.get("pk"))
            by_ak_pk[ak.get("pk")] = row
        rows.append(row)
    # authentik users without a Nextcloud account
    for u in ak_users:
        if u.get("pk") not in used_ak:
            row = row_for(u)
            by_ak_pk[u.get("pk")] = row
            rows.append(row)
    # mailboxes: by the e-mail address of the authentik user, otherwise by that of the Nextcloud account
    for row in rows:
        ak, nc = row["ak"], row["nc"]
        addr = _low(ak.get("email")) if ak else ""
        if addr in mb_by_addr and addr not in used_mb:
            row.update(mb=mb_by_addr[addr], mb_how="ak_email")
            used_mb.add(addr)
            continue
        addr = _low(nc["email"]) if nc else ""
        if addr in mb_by_addr and addr not in used_mb:
            row.update(mb=mb_by_addr[addr], mb_how="nc_email")
            used_mb.add(addr)
    for addr, mb in sorted(mb_by_addr.items()):
        if addr not in used_mb:
            row = row_for(None)
            row.update(mb=mb, mb_how="")
            rows.append(row)

    taken = set(ak_by_name)
    for row in rows:
        _fixes(row, groups_of, ak_group_names, superuser_of, taken, idp_authsource, is_admin)
        row["key"] = (f"ak:{row['ak'].get('pk')}" if row["ak"] else
                      f"nc:{row['nc']['uid']}" if row["nc"] else f"mb:{_low(row['mb'].get('username'))}")
    rows.sort(key=lambda r: (not r["fixes"], _low((r["ak"] or {}).get("username") or (r["nc"] or {}).get("uid")
                                                  or (r["mb"] or {}).get("username"))))
    counts = {k: sum(1 for r in rows if k in r["fixes"]) for k in FIXES}
    counts["ok"] = sum(1 for r in rows if not r["fixes"] and r["ak"] and (r["nc"] or r["mb"]))
    return {"rows": rows, "counts": counts, "idp_authsource": idp_authsource}


def _fixes(row: dict, groups_of: dict, ak_group_names: dict, superuser_of: set, taken: set,
           idp_authsource: str, is_admin: bool) -> None:
    ak, nc, mb = row["ak"], row["nc"], row["mb"]
    fixes, notes = row["fixes"], row["notes"]
    protected = bool(nc and ADMIN_GROUP in nc["groups"]) or bool(
        ak and (ak.get("is_superuser") or ak.get("pk") in superuser_of))
    row["protected"] = protected and not is_admin
    if protected and not is_admin:
        notes.append("Administrator-Konto – verknüpfen nur Administratoren des Servermanagers")
    if ak is None:
        if nc is not None:
            if USERNAME_RE.match(nc["uid"]):
                fixes.append("create")
                row["create_from"] = "nc"
            else:
                notes.append("Nextcloud-ID ist als authentik-Benutzername nicht möglich")
        elif mb is not None:
            local = str(mb.get("username") or "")
            if USERNAME_RE.match(local) and _low(local) not in taken:
                fixes.append("create")
                row["create_from"] = "mb"
    if nc is not None and row["nc_how"] == "email":
        # e-mail matches, user name differs: the login through authentik would create a second, empty account
        if not USERNAME_RE.match(nc["uid"]) or _low(nc["uid"]) in taken:
            notes.append("Benutzername weicht ab und ist so nicht übertragbar – bitte von Hand angleichen")
        elif is_admin:
            fixes.append("rename")
        else:
            notes.append("Benutzername weicht ab – angleichen dürfen nur Administratoren")
    if mb is not None and row["mb_how"] == "nc_email" and ak is not None:
        fixes.append("email")
    if nc is not None and (ak is not None or "create" in fixes):
        have = groups_of.get(ak.get("pk"), set()) if ak else set()
        missing = [x for x in nc["groups"] if _low(x) not in have and (x != ADMIN_GROUP or is_admin)]
        missing = [x for x in missing if not (ak_group_names.get(_low(x)) or {}).get("is_superuser")]
        if missing:
            fixes.append("groups")
            row["groups_missing"] = missing
    if mb is not None and (ak is not None or "create" in fixes):
        src = mailbox_authsource(mb)
        if not idp_authsource:
            notes.append("In der Mailcow ist kein Identity Provider eingerichtet")
        elif src != idp_authsource:
            fixes.append("authsource")
            row["mb_authsource"] = src
            row["authsource_to"] = idp_authsource
    if row["protected"]:
        row["fixes"] = []


def group_whitelist_regex(names: list[str]) -> str:
    """PCRE for user_oidc (``--group-whitelist-regex``) that matches exactly these Nextcloud group IDs."""
    parts = [re.escape(n).replace("/", "\\/") for n in sorted(set(names), key=str.lower) if n]
    return "/^(" + "|".join(parts) + ")$/" if parts else ""


def syncable_groups(nc_groups: list[str], ak_groups: list[dict], include_admin: bool = False) -> list[str]:
    """Nextcloud groups that exist in authentik under exactly the same name (user_oidc compares exactly)."""
    names = {str(x.get("name") or "") for x in ak_groups if not x.get("is_superuser")}
    return sorted([x for x in nc_groups if x in names and (include_admin or x != ADMIN_GROUP)], key=str.lower)


def apply(au: Authentik, mailcow, rows: list[dict], keys: set[str], kinds: set[str]) -> dict:
    """Carry out the chosen fixes (``kinds``) for the chosen rows (``keys``) of a fresh plan."""
    result: dict = {"done": {k: 0 for k in FIXES}, "passwords": [], "errors": [], "skipped": 0, "groups_created": []}
    group_pk = {_low(x.get("name")): x.get("pk") for x in au.groups()}
    todo = [r for r in rows if r["key"] in keys and set(r["fixes"]) & kinds]
    if len(todo) > MAX_ROWS:
        result["skipped"] = len(todo) - MAX_ROWS
        todo = todo[:MAX_ROWS]
    for row in todo:
        label = (row["ak"] or {}).get("username") or (row["nc"] or {}).get("uid") or (row["mb"] or {}).get("username")
        try:
            _apply_row(au, mailcow, row, kinds, group_pk, result)
        except (AuthentikError, MailcowError) as exc:
            result["errors"].append(f"{label}: {exc}")
    return result


def _apply_row(au: Authentik, mailcow, row: dict, kinds: set[str], group_pk: dict, result: dict) -> None:
    ak, nc, mb = row["ak"], row["nc"], row["mb"]
    fixes = [k for k in FIXES if k in row["fixes"] and k in kinds]
    if "create" in fixes:
        if row.get("create_from") == "nc":
            username, name = nc["uid"], nc["display"] or nc["uid"]
            email = str((mb or {}).get("username") or nc["email"] or "")
            active = nc["enabled"]
        else:
            username, name, email = str(mb["username"]), str(mb.get("name") or ""), str(mb["username"])
            active = bool(int(mb.get("active", 1) or 0))
        pw = security.generate_password()
        ak = au.create_user(username, name[:150], email, pw, active=active)
        result["passwords"].append((username, pw))
        result["done"]["create"] += 1
    elif ak is None:
        return   # nothing else can be done without an authentik account
    if "rename" in fixes and nc is not None:
        au.rename_user(int(ak["pk"]), nc["uid"])
        result["done"]["rename"] += 1
    if "email" in fixes and mb is not None:
        au.update_user(int(ak["pk"]), str(ak.get("name") or ak.get("username") or ""), str(mb["username"]))
        result["done"]["email"] += 1
    if "groups" in fixes and nc is not None:
        for name in row.get("groups_missing") or []:
            gpk = group_pk.get(_low(name))
            if gpk is None:
                created = au.create_group(name)
                gpk = group_pk[_low(name)] = created["pk"]
                result["groups_created"].append(name)
            au.add_to_group(gpk, int(ak["pk"]))
        result["done"]["groups"] += 1
    if "authsource" in fixes and mb is not None and mailcow is not None and row.get("authsource_to"):
        mailcow.set_mailbox(str(mb["username"]), authsource=row["authsource_to"])
        result["done"]["authsource"] += 1
