"""Take over the users and groups of a Nextcloud into authentik.

Groups are created in authentik under the same name, missing users with the Nextcloud user ID as user name, and
the group memberships are added. Because the Nextcloud SSO (app user_oidc) maps the authentik user name to the
Nextcloud user ID and adopts existing accounts ("soft auto provisioning", on by default), a user who logs in
through authentik afterwards lands in the existing Nextcloud account with all files and shares.

Nothing is removed in authentik, and nothing is changed in the Nextcloud.
"""
from __future__ import annotations

from typing import Callable

from . import security
from .authentik import USERNAME_RE, Authentik, AuthentikError

ADMIN_GROUP = "admin"
MAX_NEW_USERS = 300   # per run: keeps one request within the proxy timeout; the rest follows in the next run


def normalize_users(rows: list[dict]) -> list[dict]:
    """Users of the OCS API (id, displayname) or of occ (uid, display) -> uid, display, email, enabled, groups."""
    out = []
    for u in rows:
        uid = str(u.get("uid") or u.get("id") or "")
        if not uid:
            continue
        out.append({"uid": uid, "display": str(u.get("display") or u.get("displayname") or ""),
                    "email": str(u.get("email") or ""), "enabled": u.get("enabled") is not False,
                    "groups": [str(x) for x in (u.get("groups") or [])]})
    return sorted(out, key=lambda x: x["uid"].lower())


def plan(nc_users: list[dict], nc_groups: list[str], ak_users: list[dict], ak_groups: list[dict]) -> dict:
    """What would happen: per group and user whether it exists in authentik already."""
    ak_by_name = {str(x.get("username") or "").lower(): x for x in ak_users}
    akg_by_name = {str(x.get("name") or "").lower(): x for x in ak_groups}
    names = sorted(set(nc_groups) | {x for u in nc_users for x in u["groups"]}, key=str.lower)
    groups = []
    for name in names:
        ex = akg_by_name.get(name.lower())
        groups.append({"name": name, "exists": ex is not None, "pk": ex.get("pk") if ex else None,
                       "members": sum(1 for u in nc_users if name in u["groups"]),
                       "superuser": bool(ex and ex.get("is_superuser")), "admin": name == ADMIN_GROUP})
    users = []
    for u in nc_users:
        ex = ak_by_name.get(u["uid"].lower())
        if ex is not None:
            status = "exists"
        elif not USERNAME_RE.match(u["uid"]):
            status = "invalid"
        else:
            status = "new"
        users.append({**u, "status": status, "ak_pk": ex.get("pk") if ex else None,
                      "ak_username": ex.get("username") if ex else "", "admin": ADMIN_GROUP in u["groups"]})
    return {"groups": groups, "users": users,
            "counts": {"groups_new": sum(1 for x in groups if not x["exists"]),
                       "users_new": sum(1 for x in users if x["status"] == "new"),
                       "users_exist": sum(1 for x in users if x["status"] == "exists"),
                       "users_invalid": sum(1 for x in users if x["status"] == "invalid")}}


def apply(au: Authentik, nc_users: list[dict], nc_groups: list[str], groups: set[str], users: set[str],
          passwords: bool, existing_members: bool, log: Callable[[str], None] = lambda _m: None) -> dict:
    """Create the chosen groups and users in authentik and add the memberships.

    ``groups``/``users``: names chosen in the preview. ``passwords``: random password for new users (returned
    once), otherwise the account has no usable password yet. ``existing_members``: also add authentik users that
    existed before to their groups.
    """
    p = plan(nc_users, nc_groups, au.users(), au.groups())
    result: dict = {"groups_created": [], "users_created": [], "passwords": [], "memberships": 0, "errors": [],
                    "skipped": 0}
    # groups
    group_pk: dict[str, str] = {}
    for gr in p["groups"]:
        if gr["name"] not in groups:
            continue
        if gr["exists"]:
            group_pk[gr["name"]] = gr["pk"]
            continue
        try:
            created = au.create_group(gr["name"])
            group_pk[gr["name"]] = created["pk"]
            result["groups_created"].append(gr["name"])
            log(f"Gruppe {gr['name']} angelegt")
        except AuthentikError as exc:
            result["errors"].append(f"Gruppe {gr['name']}: {exc}")
    # users
    user_pk: dict[str, int] = {}
    for u in p["users"]:
        if u["status"] == "exists" and (existing_members or u["uid"] in users):
            user_pk[u["uid"]] = u["ak_pk"]
        if u["status"] != "new" or u["uid"] not in users:
            continue
        if len(result["users_created"]) >= MAX_NEW_USERS:
            result["skipped"] += 1
            continue
        pw = security.generate_password() if passwords else ""
        try:
            created = au.create_user(u["uid"], u["display"][:150], u["email"], pw, active=u["enabled"])
            user_pk[u["uid"]] = created["pk"]
            result["users_created"].append(u["uid"])
            if pw:
                result["passwords"].append((u["uid"], pw))
            log(f"Benutzer {u['uid']} angelegt")
        except AuthentikError as exc:
            result["errors"].append(f"Benutzer {u['uid']}: {exc}")
    # memberships: one request per group
    for name, gpk in group_pk.items():
        wanted = {user_pk[u["uid"]] for u in p["users"] if name in u["groups"] and u["uid"] in user_pk}
        if not wanted:
            continue
        try:
            result["memberships"] += au.add_group_members(gpk, wanted)
        except AuthentikError as exc:
            result["errors"].append(f"Mitglieder von {name}: {exc}")
    return result
