"""The online help (docs/) is maintained together with the code - these tests keep it consistent."""
import re
from pathlib import Path

from servermanager import __version__
from servermanager.web.views.help import DOCS_DIR, PAGES

SLUGS = [s for s, _, _ in PAGES]


def test_every_page_exists_and_every_file_is_listed():
    files = {p.stem for p in DOCS_DIR.glob("*.md")}
    assert set(SLUGS) == files, "docs/*.md und PAGES in web/views/help.py müssen übereinstimmen"


def test_internal_links_point_to_existing_pages():
    for p in DOCS_DIR.glob("*.md"):
        for target in re.findall(r"\]\(([^)#\s]+\.md)", p.read_text()):
            assert (DOCS_DIR / target).exists(), f"{p.name}: Link auf fehlende Seite {target}"


def test_changelog_has_entry_for_current_version():
    text = (DOCS_DIR / "changelog.md").read_text()
    assert re.search(rf"^## {re.escape(__version__)}\b", text, re.M), \
        f"Änderungsprotokoll: Abschnitt für Version {__version__} fehlt"


def test_pages_render_and_search(app):
    import re as _re
    from servermanager import security
    from servermanager.db import new_session
    from servermanager.models import User
    db = new_session()
    if not db.query(User).filter_by(username="helpuser").first():
        db.add(User(username="helpuser", password_hash=security.hash_password("Sehr-Geheim-123"), role="user"))
        db.commit()
    db.close()
    c = app.test_client()
    tok = _re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text).group(1)
    assert c.post("/login", data={"username": "helpuser", "password": "Sehr-Geheim-123",
                                  "csrf_token": tok}).status_code == 302
    for slug in SLUGS:
        r = c.get(f"/hilfe/{slug}")
        assert r.status_code == 200, slug
        assert ".md\"" not in r.text  # links were rewritten
    assert c.get("/hilfe/gibtsnicht").status_code == 404
    r = c.get("/hilfe/suche?q=WireGuard")
    assert r.status_code == 200 and "<mark>" in r.text
