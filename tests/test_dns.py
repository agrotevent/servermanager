"""DNS & domains: hosting.de platform (FRESH Internet) and INWX, records for Pangolin and mail."""
import pytest

from servermanager import dnsapi, dnscheck, integrations, security
from servermanager.dnsapi import DnsError, HostingDe, Inwx
from tests import mock_apis as m
from tests.test_web import login, make_user


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


@pytest.fixture(autouse=True)
def _inwx_sessions():
    dnsapi._INWX_SESSIONS.clear()
    dnsapi._INWX_LAST_TAN.clear()
    yield


def hd(mock, key=m.HD_KEY):
    return HostingDe(mock.url, key, fingerprint=mock.fingerprint)


def inwx(mock, secret=""):
    return Inwx(mock.url, m.INWX_USER, m.INWX_PASS, secret, fingerprint=mock.fingerprint)


@pytest.fixture()
def accounts(db, mock):
    from servermanager.models import DnsAccount
    a = DnsAccount(name="fresh", provider="hostingde", api_url=mock.url, secret_enc=security.encrypt(m.HD_KEY),
                   fingerprint=mock.fingerprint, monitor=True, auto_pangolin=True, default_ttl=3600, expiry_days=30)
    b = DnsAccount(name="inwx", provider="inwx", api_url=mock.url, username=m.INWX_USER,
                   secret_enc=security.encrypt(m.INWX_PASS), fingerprint=mock.fingerprint, monitor=True,
                   auto_pangolin=True, default_ttl=3600, expiry_days=30)
    db.add_all([a, b])
    db.commit()
    integrations.poll(db, a)
    integrations.poll(db, b)
    db.commit()
    yield a, b
    db.delete(a)
    db.delete(b)
    db.commit()


def test_helpers():
    assert dnsapi.txt_plain('"v=spf1 " "mx -all"') == "v=spf1 mx -all"
    assert dnsapi.txt_plain(dnsapi.txt_quoted('a"b' + "x" * 300)) == 'a"b' + "x" * 300
    assert dnsapi.zone_of("a.b.example.com", ["example.com", "b.example.com"]) == "b.example.com"
    rec = dnsapi.validate_record("example.com", {"name": "@", "type": "mx", "content": "Mail.Example.com.", "prio": "5"})
    assert rec["name"] == "example.com" and rec["content"] == "mail.example.com" and rec["prio"] == 5
    for bad in ({"type": "A", "content": "1.2.3"}, {"type": "CNAME", "name": "@", "content": "x.example.com"},
                {"type": "AAAA", "content": "1.2.3.4"}, {"type": "XYZ", "content": "x"}):
        with pytest.raises(DnsError):
            dnsapi.validate_record("example.com", bad)
    assert dnsapi.normalize_url("secure.fresh-internet.net/api/dns/v1/json", "hostingde") == "https://secure.fresh-internet.net"
    assert dnsapi.normalize_url("", "inwx") == "https://api.domrobot.com"


def test_hostingde_client(mock):
    c = hd(mock)
    assert [z["name"] for z in c.zones()] == ["example.com", "setnetz.de"]
    recs = c.records("example.com")
    spf = next(r for r in recs if r["type"] == "TXT")
    assert spf["content"] == "v=spf1 mx -all"   # stored quoted, shown as text
    assert next(r for r in recs if r["type"] == "MX")["prio"] == 10
    c.add("example.com", dnsapi.validate_record("example.com", {"name": "_dmarc", "type": "TXT",
                                                               "content": "v=DMARC1; p=none"}))
    added = mock.state.hd_updates[-1]["recordsToAdd"][0]
    assert added == {"name": "_dmarc.example.com", "type": "TXT", "content": '"v=DMARC1; p=none"', "ttl": 3600}
    assert mock.state.hd_updates[-1]["zoneConfig"]["id"] == "zc-example"   # full zone config, as the API wants
    rec = next(r for r in c.records("example.com") if r["name"] == "_dmarc.example.com")
    c.update("example.com", rec, {**rec, "content": "v=DMARC1; p=quarantine"})
    rec = next(r for r in c.records("example.com") if r["name"] == "_dmarc.example.com")
    assert rec["content"] == "v=DMARC1; p=quarantine"
    c.delete("example.com", rec)
    assert not [r for r in c.records("example.com") if r["name"] == "_dmarc.example.com"]
    doms = {d["name"]: d for d in c.domains()}
    assert doms["example.com"]["expires"] == "2027-03-01" and doms["example.com"]["transfer_lock"]
    assert doms["alt-domain.de"]["deletion"] == "2026-10-20"
    with pytest.raises(DnsError, match="API-Schlüssel"):
        hd(mock, "wrong").zones()


def test_inwx_client(mock):
    st = mock.state
    c = inwx(mock)
    assert [z["name"] for z in c.zones()] == ["inwx-kunde.de"]
    assert [r["type"] for r in c.records("inwx-kunde.de")] == ["A"]   # SOA is left out
    c.add("inwx-kunde.de", dnsapi.validate_record("inwx-kunde.de", {"name": "www", "type": "CNAME",
                                                                   "content": "inwx-kunde.de"}))
    www = next(r for r in c.records("inwx-kunde.de") if r["name"] == "www.inwx-kunde.de")
    c.update("inwx-kunde.de", www, {**www, "content": "other.example.com"})
    www = next(r for r in c.records("inwx-kunde.de") if r["name"] == "www.inwx-kunde.de")
    assert www["content"] == "other.example.com"
    c.delete("inwx-kunde.de", www)
    d = c.domains()[0]
    assert d["expires"] == "2026-10-30" and d["renew"] == "automatisch" and d["nameservers"] == ["ns.inwx.de", "ns2.inwx.de"]
    # the session is reused by the next client (no new login, which would need a new TAN)
    logins = st.inwx_logins
    inwx(mock).zones()
    assert st.inwx_logins == logins
    # two-factor: without the secret a clear message, with it the TAN is computed
    dnsapi._INWX_SESSIONS.clear()
    st.inwx_tfa = True
    try:
        with pytest.raises(DnsError, match="Zwei-Faktor"):
            inwx(mock).zones()
        assert [z["name"] for z in inwx(mock, m.INWX_TOTP).zones()] == ["inwx-kunde.de"]
    finally:
        st.inwx_tfa = False
    with pytest.raises(DnsError, match="Anmeldung fehlgeschlagen"):
        dnsapi._INWX_SESSIONS.clear()
        Inwx(mock.url, m.INWX_USER, "wrong", fingerprint=mock.fingerprint).zones()


def test_poll_and_alerts(accounts):
    a, b = accounts
    assert a.status == "online" and b.status == "online", (a.status_message, b.status_message)
    assert a.data["zones"] == ["example.com", "setnetz.de"] and len(a.data["domains"]) == 2
    assert [x["key"] for x in a.alerts] == ["del:alt-domain.de"]       # runs out in 12 days, not renewed
    assert b.data["zones"] == ["inwx-kunde.de"] and not b.alerts           # renews automatically
    assert b.data["expiring"] == ["inwx-kunde.de"]


def test_pages_records_and_rights(app, db, mock, accounts):
    from servermanager.models import KIND_DNS, LEVEL_OPERATE, IntegrationAccess
    a, _b = accounts
    make_user(db, "dns-admin", "admin")
    c = login(app, "dns-admin")
    assert "DNS & Domains" in c.get("/dns/").text
    page = c.get(f"/dns/{a.id}").text
    assert "alt-domain.de" in page and "endet 2026-10-20" in page
    page = c.get(f"/dns/{a.id}/zone/example.com").text
    assert 'data-dialog-open="#rec-edit"' in page and "v=spf1 mx -all" in page
    r = c.post(f"/dns/{a.id}/zone/example.com/records", data={"action": "add", "name": "app", "type": "A",
                                                               "content": "203.0.113.9", "ttl": "600",
                                                               "csrf_token": c.csrf}, follow_redirects=True)
    assert "A app.example.com angelegt" in r.text
    rec = next(x for x in mock.state.hd_zones["example.com"]["records"] if x["name"] == "app.example.com")
    r = c.post(f"/dns/{a.id}/zone/example.com/records", data={"action": "edit", "id": rec["id"], "name": "app",
                                                               "type": "A", "content": "203.0.113.10", "ttl": "600",
                                                               "csrf_token": c.csrf}, follow_redirects=True)
    assert "geändert" in r.text and rec["content"] == "203.0.113.10"
    r = c.post(f"/dns/{a.id}/zone/example.com/records", data={"action": "add", "name": "www", "type": "A",
                                                               "content": "203.0.113.9", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "CNAME" in r.text   # next to a CNAME nothing else
    ns = next(x for x in mock.state.hd_zones["example.com"]["records"] if x["type"] == "NS")
    r = c.post(f"/dns/{a.id}/zone/example.com/records", data={"action": "delete", "id": ns["id"],
                                                               "csrf_token": c.csrf}, follow_redirects=True)
    assert "NS-Einträge der Zone" in r.text
    c.post(f"/dns/{a.id}/zone/example.com/records", data={"action": "delete", "id": rec["id"], "csrf_token": c.csrf})
    assert not [x for x in mock.state.hd_zones["example.com"]["records"] if x["name"] == "app.example.com"]
    assert c.get(f"/dns/{a.id}/zone/fremd.de").status_code == 404
    u = make_user(db, "dns-op")
    db.add(IntegrationAccess(user_id=u.id, kind=KIND_DNS, obj_id=a.id, level=LEVEL_OPERATE))
    db.commit()
    op = login(app, "dns-op")
    assert 'data-dialog-open="#rec-edit"' not in op.get(f"/dns/{a.id}/zone/example.com").text
    assert op.post(f"/dns/{a.id}/zone/example.com/records", data={"action": "add", "name": "x", "type": "A",
                                                                   "content": "1.2.3.4", "csrf_token": op.csrf}
                   ).status_code == 403
    db.query(IntegrationAccess).filter_by(user_id=u.id).delete()
    db.commit()


def test_pangolin_records(app, db, mock, accounts):
    from servermanager.models import PangolinServer
    a, _b = accounts
    st = mock.state
    pg = PangolinServer(name="pg-dns", api_url="https://api.pangolin.example.com", org_id="o", role="primary",
                        dns_target="pangolin.example.com",
                        cache={"published": ["cloud.example.com", "git.setnetz.de", "www.example.com"]})
    db.add(pg)
    db.commit()
    try:
        assert dnscheck.pangolin_target(pg) == "pangolin.example.com"
        # after publishing: missing CNAME is created in the managed zone
        msg = dnscheck.ensure_published(db, "new.example.com", pg)
        assert "CNAME new.example.com → pangolin.example.com" in msg
        assert any(r["name"] == "new.example.com" and r["content"] == "pangolin.example.com"
                   for r in st.hd_zones["example.com"]["records"])
        assert "eingerichtet" in dnscheck.ensure_published(db, "app.setnetz.de", pg)   # wildcard
        assert dnscheck.ensure_published(db, "x.unbekannt.de", pg) == ""             # zone not managed
        make_user(db, "dns-admin", "admin")
        c = login(app, "dns-admin")
        page = c.get(f"/dns/{a.id}?tab=check").text
        # only deviations: missing cloud, wrong www (-> example.com); the wildcard name that is fine is hidden
        assert "cloud.example.com" in page and "abweichend" in page and "über Platzhalter" not in page
        assert "in Ordnung ausgeblendet" in page
        assert "über Platzhalter" in c.get(f"/dns/{a.id}?tab=check&all=1").text
        r = c.post(f"/dns/{a.id}/fix", data={"key": f"pg:{pg.id}:cloud.example.com", "csrf_token": c.csrf},
                   follow_redirects=True)
        assert "CNAME cloud.example.com → pangolin.example.com angelegt" in r.text
        assert "<td class=\"mono\">cloud.example.com</td>" not in c.get(f"/dns/{a.id}?tab=check").text   # fixed: gone
        r = c.post(f"/dns/{a.id}/fix", data={"key": f"pg:{pg.id}:www.example.com", "csrf_token": c.csrf},
                   follow_redirects=True)
        assert "ersetzt" in r.text
        www = [x for x in st.hd_zones["example.com"]["records"] if x["name"] == "www.example.com"]
        assert [(x["type"], x["content"]) for x in www] == [("CNAME", "pangolin.example.com")]
    finally:
        db.delete(pg)
        db.commit()


def test_mail_dns(app, db, mock, accounts):
    from servermanager.models import KIND_DNS, KIND_MAILCOW, LEVEL_OPERATE, LEVEL_VIEW, IntegrationAccess, MailcowServer
    a, _b = accounts
    st = mock.state
    mc = MailcowServer(name="mc-dns", api_url=mock.url, api_key_enc=security.encrypt(m.MC_KEY), fingerprint=mock.fingerprint,
                       public_url="https://webmail.example.com", mail_hostname="mail.example.com",
                       mail_public_ip="198.51.100.25")
    db.add(mc)
    db.commit()
    try:
        make_user(db, "dns-admin", "admin")
        c = login(app, "dns-admin")
        page = c.get(f"/mailcow/{mc.id}?tab=dns").text
        assert "DNS-Einträge für Mail" in page and "v=DKIM1;k=rsa" in page and "_dmarc.example.com" in page
        zones = dnscheck.Zones(db, [a])
        rows = {r["key"].rsplit(":", 1)[-1]: r for r in dnscheck.mail_rows(
            zones, mc, ["example.com"], {"example.com": st.mc_dkim["example.com"]})}
        zones.close()
        assert rows["host"]["state"] == "missing" and rows["mx"]["state"] == "wrong" and rows["spf"]["state"] == "ok"
        assert rows["dkim"]["state"] == "missing" and rows["dmarc"]["state"] == "missing"
        # an operator may create missing records, replacing a wrong one needs full access
        u = make_user(db, "mail-dns-op")
        db.add_all([IntegrationAccess(user_id=u.id, kind=KIND_DNS, obj_id=a.id, level=LEVEL_OPERATE),
                    IntegrationAccess(user_id=u.id, kind=KIND_MAILCOW, obj_id=mc.id, level=LEVEL_VIEW)])
        db.commit()
        op = login(app, "mail-dns-op")
        r = op.post(f"/mailcow/{mc.id}/dns-fix", data={"key": rows["dkim"]["key"], "csrf_token": op.csrf},
                    follow_redirects=True)
        assert "TXT dkim._domainkey.example.com" in r.text
        dk = next(x for x in st.hd_zones["example.com"]["records"] if x["name"] == "dkim._domainkey.example.com")
        assert dk["content"].startswith('"v=DKIM1;k=rsa')     # quoted for the API
        r = op.post(f"/mailcow/{mc.id}/dns-fix", data={"key": rows["mx"]["key"], "csrf_token": op.csrf},
                    follow_redirects=True)
        assert "Vollzugriff" in r.text
        r = c.post(f"/mailcow/{mc.id}/dns-fix", data={"key": rows["mx"]["key"], "csrf_token": c.csrf},
                   follow_redirects=True)
        assert "MX example.com → mail.example.com angelegt (1 alte(r)" in r.text
        mx = [x for x in st.hd_zones["example.com"]["records"] if x["type"] == "MX"]
        assert [(x["content"], x.get("priority")) for x in mx] == [("mail.example.com", 10)]
        r = c.post(f"/mailcow/{mc.id}/dns-fix", data={"key": "mc:999:example.com:mx", "csrf_token": c.csrf},
                   follow_redirects=True)
        assert "nichts zu tun" in r.text
        db.query(IntegrationAccess).filter_by(user_id=u.id).delete()
        db.commit()
    finally:
        db.delete(mc)
        db.commit()


def test_unknown_host_message():
    c = HostingDe("https://secure.fresh-internet.invalid", m.HD_KEY, timeout=5)
    with pytest.raises(DnsError, match="gibt es im DNS nicht.*secure.fresh-internet.net"):
        c.zones()


def test_mail_host_per_domain(app, db, mock, accounts):
    """Mail host name 'post.[domain]': every mail domain gets its own MX/A/autodiscover target, and mailcow needs
    'post.*' in ADDITIONAL_SAN for the certificate."""
    from servermanager.mailcow import is_mail_host, mail_host_for, san_entry
    from servermanager.models import MailcowServer, System
    a, _b = accounts
    st = mock.state
    assert mail_host_for("post.[domain]", "example.com") == "post.example.com" and san_entry("post.[domain]") == "post.*"
    assert is_mail_host("post.[domain]", "post.example.org") and not is_mail_host("post.[domain]", "webmail.example.org")
    host = System(name="mail-sys", host="10.20.0.30", types=["debian", "mailcow"],
                  facts={"mailcow_san": "smtp.*", "mailcow_hostname": "post.example.com"})
    db.add(host)
    db.flush()
    mc = MailcowServer(name="mc-tpl", api_url=mock.url, api_key_enc=security.encrypt(m.MC_KEY), fingerprint=mock.fingerprint,
                       public_url="https://webmail.example.com", mail_hostname="post.[domain]",
                       mail_public_ip="198.51.100.25", system_id=host.id)
    db.add(mc)
    db.commit()
    try:
        zones = dnscheck.Zones(db, [a])
        rows = {r["key"].split(":", 2)[-1]: r for r in dnscheck.mail_rows(zones, mc, ["example.com"], {})}
        zones.close()
        assert rows["example.com:host"]["host"] == "post.example.com" and rows["example.com:host"]["expected"] == "198.51.100.25"
        assert rows["example.com:mx"]["expected"] == "10 post.example.com"
        assert rows["example.com:autodiscover"]["expected"] == "post.example.com"
        assert rows["example.com:srv"]["expected"] == "0 1 443 post.example.com"
        make_user(db, "dns-admin", "admin")
        c = login(app, "dns-admin")
        page = c.get(f"/mailcow/{mc.id}?tab=dns").text
        assert "ADDITIONAL_SAN fehlt post.*" in page and "post.* ergänzen" in page
        assert "<small>post.example.com</small></td><td><small>A</small>" in page   # missing A record is listed
        r = c.post(f"/mailcow/{mc.id}/dns-fix", data={"key": rows["example.com:host"]["key"], "csrf_token": c.csrf},
                   follow_redirects=True)
        assert "A post.example.com → 198.51.100.25 angelegt" in r.text
        assert any(x["name"] == "post.example.com" and x["content"] == "198.51.100.25"
                   for x in st.hd_zones["example.com"]["records"])
        # fixed: the row is gone from the overview of deviations
        assert "<small>post.example.com</small></td><td><small>A</small>" not in c.get(f"/mailcow/{mc.id}?tab=dns").text
        host.facts = {"mailcow_san": "smtp.*,post.*"}
        db.commit()
        assert "ADDITIONAL_SAN enthält post.*" in c.get(f"/mailcow/{mc.id}?tab=dns").text
        # form: template accepted, nonsense not
        r = c.post(f"/mailcow/{mc.id}/edit", data={"name": "mc-tpl", "api_url": mock.url, "mail_hostname": "post.[domain].x",
                                                   "csrf_token": c.csrf}, follow_redirects=True)
        assert "Ungültiger Mail-Hostname" in r.text
    finally:
        st.hd_zones["example.com"]["records"] = [x for x in st.hd_zones["example.com"]["records"]
                                                 if x["name"] != "post.example.com"]
        db.delete(mc)
        db.delete(host)
        db.commit()
