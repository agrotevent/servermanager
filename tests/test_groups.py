"""User groups: members by hand or through authentik, rights on systems and modules (also "all")."""
from sqlalchemy import create_engine, text

from servermanager import access
from servermanager.models import (KIND_PVE, KIND_SYSTEM, GroupRight, IntegrationAccess, PveServer, System, User,
                                  UserGroup, UserGroupMember)
from tests.test_web import login, make_user


def test_migration_of_hetzner_group_rights():
    from servermanager import migrations
    from servermanager.db import Base
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE group_access (id INTEGER PRIMARY KEY, group_name VARCHAR(150), kind VARCHAR(16), "
                          "obj_id INTEGER, level VARCHAR(16), created_at DATETIME)"))
        conn.execute(text("INSERT INTO group_access (group_name, kind, obj_id, level) VALUES "
                          "('Hetzner-Technik', 'hetzner_srv', 3, 'operate'), ('hetzner-technik', 'hetzner', 1, 'view'), "
                          "('admins', 'hcloud', 2, 'full')"))
        migrations._v12(conn)
        groups = conn.execute(text("SELECT id, name, sso_group FROM user_groups ORDER BY name")).fetchall()
        assert [(g[1], g[2]) for g in groups] == [("Hetzner-Technik", "Hetzner-Technik"), ("admins", "admins")]
        rights = conn.execute(text("SELECT kind, obj_id, level FROM group_rights ORDER BY kind")).fetchall()
        assert [tuple(r) for r in rights] == [("hcloud", 2, "full"), ("hetzner", 1, "view"), ("hetzner_srv", 3, "operate")]
        assert conn.execute(text("SELECT count(*) FROM group_access")).scalar() == 0
        migrations._v12(conn)   # nothing left to take over
        assert conn.execute(text("SELECT count(*) FROM group_rights")).scalar() == 3


def test_group_rights_in_access_checks(db):
    s1, s2 = System(name="grp-a", host="10.9.0.1", types=["debian"]), System(name="grp-b", host="10.9.0.2", types=["debian"])
    pve = PveServer(name="grp-pve", api_url="https://10.9.0.9:8006")
    u = User(username="grp-user", password_hash="x", role="user")
    db.add_all([s1, s2, pve, u])
    db.flush()
    grp = UserGroup(name="Technik", sso_group="ak-technik")
    db.add(grp)
    db.flush()
    try:
        assert access.system_level(db, u, s1.id) is None and not access.levels_map(db, u)
        db.add(GroupRight(group_id=grp.id, kind=KIND_SYSTEM, obj_id=s1.id, level="view"))
        db.add(GroupRight(group_id=grp.id, kind=KIND_PVE, obj_id=0, level="operate"))   # all Proxmox servers
        db.flush()
        assert access.system_level(db, u, s1.id) is None          # not a member yet
        u.sso_groups = ["AK-Technik"]                              # member through authentik
        assert access.system_level(db, u, s1.id) == "view" and access.system_level(db, u, s2.id) is None
        assert access.integration_level(db, u, KIND_PVE, pve.id) == "operate"
        assert access.integration_levels(db, u, KIND_PVE)[pve.id] == "operate"
        assert "pve" in access.any_integration_access(db, u)
        u.sso_groups = []
        db.add(UserGroupMember(user_id=u.id, group_id=grp.id))   # member by hand
        db.flush()
        assert access.system_level(db, u, s1.id) == "view"
        # "all systems" includes systems added later; the highest level counts
        other = UserGroup(name="Alle Systeme")
        db.add(other)
        db.flush()
        db.add_all([GroupRight(group_id=other.id, kind=KIND_SYSTEM, obj_id=0, level="operate"),
                    UserGroupMember(user_id=u.id, group_id=other.id)])
        s3 = System(name="grp-c", host="10.9.0.3", types=["debian"])
        db.add(s3)
        db.flush()
        assert access.levels_map(db, u) == {s1.id: "operate", s2.id: "operate", s3.id: "operate"}
        assert [s.name for s in access.accessible_systems(db, u, "operate") if s.name.startswith("grp-")] == \
            ["grp-a", "grp-b", "grp-c"]
        db.add(IntegrationAccess(user_id=u.id, kind=KIND_PVE, obj_id=pve.id, level="full"))
        db.flush()
        assert access.integration_level(db, u, KIND_PVE, pve.id) == "full"   # own right is higher
        access.remove_rights(db, KIND_SYSTEM, s1.id)
        db.flush()
        assert db.query(GroupRight).filter_by(kind=KIND_SYSTEM, obj_id=s1.id).count() == 0
    finally:
        db.rollback()


def test_group_pages(app, db):
    make_user(db, "grp-admin", "admin")
    member = make_user(db, "grp-member")
    s = System(name="grp-web", host="10.9.1.1", types=["debian"])
    db.add(s)
    db.commit()
    c = login(app, "grp-admin")
    try:
        assert "Neue Gruppe" in c.get("/users/").text
        page = c.get("/users/groups/new?sso_group=ak-ops").text
        assert 'value="ak-ops"' in page and f'name="r_system_{s.id}"' in page and 'name="r_pve_0"' in page
        r = c.post("/users/groups/new", data={"name": "Ops", "sso_group": "ak-ops", "description": "Betrieb",
                                             "members": [str(member.id)], f"r_system_{s.id}": "operate",
                                             "r_dns_0": "view", "csrf_token": c.csrf}, follow_redirects=True)
        assert "Gruppe „Ops“ angelegt" in r.text
        grp = db.query(UserGroup).filter_by(name="Ops").one()
        assert {(x.kind, x.obj_id, x.level) for x in db.query(GroupRight).filter_by(group_id=grp.id)} == {
            ("system", s.id, "operate"), ("dns", 0, "view")}
        r = c.post("/users/groups/new", data={"name": "ops", "sso_group": "", "csrf_token": c.csrf}, follow_redirects=True)
        assert "gibt es schon" in r.text
        # the member sees the system and may operate it
        m = login(app, "grp-member")
        assert m.get(f"/systems/{s.id}").status_code == 200
        assert 'href="/dns/"' in m.get("/").text
        # user form: groups by hand
        page = c.get(f"/users/{member.id}").text
        assert f'name="groups" value="{grp.id}" checked' in page
        c.post(f"/users/{member.id}", data={"display_name": "", "email": "", "role": "user", "active": "1",
                                            "groups_shown": "1", "csrf_token": c.csrf})
        assert db.query(UserGroupMember).filter_by(group_id=grp.id).count() == 0
        assert m.get(f"/systems/{s.id}").status_code == 403
        r = c.post(f"/users/groups/{grp.id}/delete", data={"csrf_token": c.csrf}, follow_redirects=True)
        assert "gelöscht" in r.text and not db.query(GroupRight).filter_by(group_id=grp.id).count()
    finally:
        db.rollback()
        for grp in db.query(UserGroup).filter(UserGroup.name.in_(["Ops", "ops"])):
            db.delete(grp)
        db.delete(db.get(System, s.id))
        db.commit()
