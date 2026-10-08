"""Modules not in use are left out of the navigation, the help and the rights forms."""
from servermanager import settings
from tests.test_web import login, make_user


def test_zabbix_hidden_by_default_and_shown_again(app, db):
    make_user(db, "mod-admin", "admin")
    c = login(app, "mod-admin")
    page = c.get("/").text
    assert 'href="/zabbix/"' not in page and 'href="/pangolin/"' in page
    assert 'href="/hilfe/zabbix"' not in c.get("/hilfe/").text and 'href="/hilfe/zammad"' in c.get("/hilfe/").text
    assert c.get("/hilfe/zabbix").status_code == 200
    assert "Zabbix &amp; Tickets" not in c.get("/users/groups/new").text
    assert c.get("/zabbix/").status_code == 200   # the pages stay reachable
    page = c.get("/settings").text
    assert 'name="modules" value="zabbix" >' in page and 'name="modules" value="pve" checked' in page
    shown = [k for k in settings.HIDEABLE_MODULES if k not in ("zabbix", "easybell")]
    r = c.post("/settings/modules", data={"modules": shown, "csrf_token": c.csrf}, follow_redirects=True)
    assert "Module gespeichert" in r.text
    assert settings.get(db, "ui.hidden_modules") == ["easybell", "zabbix"]
    r = c.post("/settings/modules", data={"modules": list(settings.HIDEABLE_MODULES), "csrf_token": c.csrf},
               follow_redirects=True)
    assert 'href="/zabbix/"' in r.text and settings.get(db, "ui.hidden_modules") == []
    c.post("/settings/modules", data={"modules": [k for k in settings.HIDEABLE_MODULES if k != "zabbix"],
                                            "csrf_token": c.csrf})
