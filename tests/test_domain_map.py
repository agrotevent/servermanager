"""Primary -> backup domain mapping for mirrored Pangolin publications."""
import pytest

from servermanager import optimize, security
from servermanager.pangolin import Pangolin, PangolinError, render_subdomain, validate_template
from tests import mock_apis as m
from tests.test_integrations import _run


@pytest.mark.parametrize("template,sub,base,expected", [
    ("{sub}", "cloud", "example.com", "cloud"),
    ("{sub}-{domain}", "cloud", "firma.de", "cloud-firma"),
    ("{sub}.{domain}", "a.b", "firma.de", "a.b.firma"),
    ("{sub}-{domain}", "", "firma.de", "firma"),
    ("{sub}", "", "example.com", ""),
    ("{sub}-{base}", "wiki", "kunde.co.uk", "wiki-kunde-co-uk"),
])
def test_render_subdomain(template, sub, base, expected):
    assert render_subdomain(template, sub, base) == expected


@pytest.mark.parametrize("template", ["{evil}", "{sub}/x", "", "{sub}_x"])
def test_invalid_templates(template):
    if template == "":
        assert validate_template(template) == "{sub}"
        return
    with pytest.raises(PangolinError):
        validate_template(template)


@pytest.fixture()
def pair(db):
    from servermanager.models import PangolinServer
    a, b = m.MockServer().start(), m.MockServer().start()
    a.state.domains = [{"domainId": "d-ex", "baseDomain": "example.com"}, {"domainId": "d-fi", "baseDomain": "firma.de"}]
    b.state.domains = [{"domainId": "b-main", "baseDomain": "backup-example.net"},
                       {"domainId": "b-fi", "baseDomain": "firma-backup.de"}]
    b.state.sites = [{"siteId": 7, "name": "newt-backup", "online": True}]
    prim = PangolinServer(name="dm-prim", api_url=a.url, org_id=m.PG_ORG, api_key_enc=security.encrypt(m.PG_KEY),
                          fingerprint=a.fingerprint, default_site_id=1, default_domain_id="d-ex", role="primary")
    back = PangolinServer(name="dm-back", api_url=b.url, org_id=m.PG_ORG, api_key_enc=security.encrypt(m.PG_KEY),
                          fingerprint=b.fingerprint, default_site_id=7, default_domain_id="b-main", role="backup",
                          domain_map={"example.com": {"domain_id": "b-main", "template": "{sub}"},
                                      "firma.de": {"domain_id": "b-main", "template": "{sub}-{domain}"}})
    db.add_all([prim, back])
    db.commit()
    client = Pangolin(a.url, m.PG_KEY, m.PG_ORG, fingerprint=a.fingerprint)
    client.publish("Cloud Ex", "http", 1, "10.30.0.10", 443, "https", "cloud", "d-ex", sso=True)
    client.publish("Cloud Firma", "http", 1, "10.30.0.11", 443, "https", "cloud", "d-fi", sso=True)
    client.publish("Firma Web", "http", 1, "10.30.0.12", 80, "http", "", "d-fi")
    # only these two Pangolin instances take part in this test
    others = db.query(PangolinServer).filter(PangolinServer.id.notin_([prim.id, back.id])).all()
    saved = [(o, o.role) for o in others]
    for o in others:
        o.role = "inactive"
    db.commit()
    yield a, b, prim, back
    for o, role in saved:
        o.role = role
    db.delete(prim)
    db.delete(back)
    db.commit()
    a.stop()
    b.stop()


def test_mirror_follows_mapping(db, pair):
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job
    a, b, prim, back = pair
    result = optimize.scan(db)
    mirrors = {p["params"]["ip"]: p for p in result["proposals"] if p["id"].startswith("pangolin:mirror:10.30.")}
    assert mirrors["10.30.0.10"]["params"]["subdomain"] == "cloud"
    assert mirrors["10.30.0.11"]["params"]["subdomain"] == "cloud-firma"
    assert mirrors["10.30.0.12"]["params"]["subdomain"] == "firma"          # base domain -> {domain}
    assert "cloud.firma.de → cloud-firma.backup-example.net" in mirrors["10.30.0.11"]["title"]
    items = [{"id": p["id"], "title": p["title"], "action": p["action"], "params": p["params"], "obj": p["obj"],
              "inputs": {}} for p in mirrors.values()]
    job = enqueue(db, kind="optimize", title="mirror", payload={"items": items})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success", log_path(job.id).read_text()
    names = {r["fullDomain"] for r in b.state.resources.values()}
    assert {"cloud.backup-example.net", "cloud-firma.backup-example.net", "firma.backup-example.net"} <= names
    # the SSO setting is taken over
    assert next(r for r in b.state.resources.values() if r["fullDomain"] == "cloud-firma.backup-example.net")["sso"]


def test_collision_is_refused(db, pair):
    from servermanager.jobs import enqueue
    from servermanager.models import Job
    a, b, prim, back = pair
    back.domain_map = {"example.com": {"domain_id": "b-main", "template": "{sub}"},
                       "firma.de": {"domain_id": "b-main", "template": "{sub}"}}
    db.commit()
    result = optimize.scan(db)
    mirrors = [p for p in result["proposals"] if p["id"] in ("pangolin:mirror:10.30.0.10:443",
                                                              "pangolin:mirror:10.30.0.11:443")]
    assert len(mirrors) == 2 and {p["params"]["subdomain"] for p in mirrors} == {"cloud"}
    items = [{"id": p["id"], "title": p["title"], "action": p["action"], "params": p["params"], "obj": p["obj"],
              "inputs": {}} for p in mirrors]
    job = enqueue(db, kind="optimize", title="mirror", payload={"items": items})
    db.commit()
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    assert "1 fehlgeschlagen" in job.summary
    assert [r["fullDomain"] for r in b.state.resources.values()].count("cloud.backup-example.net") == 1


def test_separate_backup_domain_and_form(app, db, pair):
    from tests.test_web import login, make_user
    a, b, prim, back = pair
    make_user(db, "dm-admin", "admin")
    c = login(app, "dm-admin")
    page = c.get(f"/pangolin/{back.id}/edit").text
    assert "Domain-Zuordnung" in page and "firma.de" in page and "cloud-firma.backup-example.net" in page
    form = {"name": back.name, "api_url": b.url, "fingerprint": b.fingerprint, "org_id": m.PG_ORG,
            "role": "backup", "default_site_id": "7", "default_domain_id": "b-main", "monitor": "1",
            "map_count": "2", "map_0_base": "example.com", "map_0_domain": "b-main", "map_0_template": "{sub}",
            "map_1_base": "firma.de", "map_1_domain": "b-fi", "map_1_template": "{sub}", "csrf_token": c.csrf}
    assert c.post(f"/pangolin/{back.id}/edit", data=form).status_code == 302
    db.expire_all()
    assert back.domain_map["firma.de"] == {"domain_id": "b-fi", "template": "{sub}"}
    r = c.get("/pangolin/services").text
    assert "cloud.firma-backup.de" in r and "firma-backup.de" in r
    form["map_1_template"] = "{bad}"
    r = c.post(f"/pangolin/{back.id}/edit", data=form, follow_redirects=True)
    assert "Platzhalter" in r.text
    db.expire_all()
    assert back.domain_map["firma.de"]["template"] == "{sub}"
    # mirror via the overview uses the mapped domain
    r = c.post("/pangolin/services/mirror", data={"pangolin_id": str(back.id), "name": "Cloud Firma",
               "ip": "10.30.0.11", "port": "443", "protocol": "http", "method": "https", "subdomain": "cloud",
               "domain_id": "b-fi", "sso": "1", "csrf_token": c.csrf}, follow_redirects=True)
    assert "cloud.firma-backup.de" in r.text
    r = c.post("/pangolin/services/mirror", data={"pangolin_id": str(back.id), "name": "dup", "ip": "10.30.0.11",
               "port": "443", "protocol": "http", "subdomain": "cloud", "domain_id": "b-fi", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "bereits vergeben" in r.text
