"""Corporate design: colours as CSS variables, logo and font served by the application, validation."""
import pytest

from servermanager import branding, settings
from tests.test_web import login, make_user

PNG = (b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#e30613"/></svg>'


def test_colour_helpers():
    assert branding.check_hex("E30613", "x") == "#e30613"
    with pytest.raises(branding.BrandError):
        branding.check_hex("red", "Hauptfarbe")
    assert branding.on_color("#ffffff") == "#0f172a" and branding.on_color("#1d3557") == "#ffffff"
    assert branding.mix("#000000", "#ffffff", .5) == "#808080"
    assert round(branding.contrast("#000000", "#ffffff")) == 21


def test_css_from_settings(db):
    try:
        assert branding.css(db) == ""  # nothing configured: default theme untouched
        settings.set(db, "brand.primary", "#e30613")
        settings.set(db, "brand.sidebar", "#1d1d1b")
        settings.set(db, "brand.font", "arial")
        css = branding.css(db)
        assert "--primary: #e30613" in css and "--sidebar: #1d1d1b" in css and "--on-primary: #ffffff" in css
        assert "--sidebar-strong: #ffffff" in css and "Arial" in css and "prefers-color-scheme: dark" in css
        settings.set(db, "brand.sidebar", "#f4f4f4")  # light sidebar: dark text
        assert "--sidebar-strong: #0f172a" in branding.css(db)
    finally:
        for k in ("brand.primary", "brand.sidebar", "brand.font"):
            settings.set(db, k, settings.DEFAULTS[k])
        db.commit()


def test_store_validates_files(db):
    with pytest.raises(branding.BrandError, match="SVG, PNG"):
        branding.store(db, "logo", b"GIF89a....")
    with pytest.raises(branding.BrandError, match="Skripte"):
        branding.store(db, "logo", b'<svg onload="alert(1)"></svg>')
    with pytest.raises(branding.BrandError, match="Skripte"):
        branding.store(db, "logo", b"<svg><script>alert(1)</script></svg>")
    with pytest.raises(branding.BrandError, match="zu groß"):
        branding.store(db, "logo", PNG + b"\x00" * branding.MAX_LOGO)
    with pytest.raises(branding.BrandError, match="WOFF2"):
        branding.store(db, "font", b"not a font")
    assert branding.store(db, "font", b"wOF2" + b"\x00" * 32) == "font/woff2"
    branding.remove(db, "font")
    db.rollback()


def test_admin_sets_corporate_design(app, db):
    import io
    make_user(db, "brand-admin", "admin")
    c = login(app, "brand-admin")
    try:
        page = c.get("/settings").text
        assert "Erscheinungsbild (Corporate Design)" in page
        r = c.post("/settings/appearance", data={
            "brand_primary": "E30613", "brand_sidebar": "#1d1d1b", "brand_accent": "", "brand_font": "arial",
            "brand_logo_only": "1", "brand_logo_file": (io.BytesIO(SVG), "logo.svg"), "csrf_token": c.csrf},
            content_type="multipart/form-data", follow_redirects=True)
        assert "Erscheinungsbild gespeichert" in r.text, r.text[:1500]
        assert "--primary: #e30613" in r.text and 'class="brand-logo"' in r.text and "logo-only" in r.text
        logo = r.text.split('class="brand-logo" src="')[1].split('"')[0]
        resp = app.test_client().get(logo)  # public: needed on the login page
        assert resp.status_code == 200 and resp.mimetype == "image/svg+xml" and resp.data == SVG
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
        assert "immutable" in resp.headers["Cache-Control"]
        login_page = app.test_client().get("/login").text
        assert 'class="brand-logo"' in login_page and "--primary: #e30613" in login_page
        assert f'rel="icon" href="{logo}"' in login_page
        # invalid input changes nothing
        r = c.post("/settings/appearance", data={"brand_primary": "rot", "csrf_token": c.csrf}, follow_redirects=True)
        assert "Farbe als #RRGGBB" in r.text and settings.get(db, "brand.primary") == "#e30613"
        r = c.post("/settings/appearance", data={"brand_font": "custom", "csrf_token": c.csrf}, follow_redirects=True)
        assert "Schriftdatei" in r.text
        r = c.post("/settings/appearance", data={
            "brand_font": "custom", "brand_font_file": (io.BytesIO(b"wOF2" + b"\x00" * 32), "brand.woff2"),
            "csrf_token": c.csrf}, content_type="multipart/form-data", follow_redirects=True)
        assert '@font-face { font-family: "SM Brand"' in r.text
        assert app.test_client().get("/branding/font").mimetype == "font/woff2"
        # reset
        r = c.post("/settings/appearance", data={"reset": "1", "csrf_token": c.csrf}, follow_redirects=True)
        assert "zurückgesetzt" in r.text and "--primary: #e30613" not in r.text
        assert app.test_client().get("/branding/logo").status_code == 404
        # non-admins cannot change it
        make_user(db, "brand-user")
        u = login(app, "brand-user")
        assert u.post("/settings/appearance", data={"brand_primary": "#000000", "csrf_token": u.csrf}).status_code \
            in (302, 403)
        assert not settings.get(db, "brand.primary")
    finally:
        for k in ("brand.primary", "brand.sidebar", "brand.accent", "brand.font", "brand.logo_only",
                  "brand.logo_data", "brand.logo_type", "brand.font_data", "brand.font_type"):
            settings.set(db, k, settings.DEFAULTS[k])
        db.commit()


def test_light_logo_on_the_login_card(app, db):
    try:
        branding.store(db, "logo", SVG)
        branding.store(db, "logo_light", PNG)
        db.commit()
        page = app.test_client().get("/login").text
        assert "/branding/logo_light?v=" in page  # login card: light variant
        r = app.test_client().get(page.split('class="brand-logo" src="')[1].split('"')[0])
        assert r.mimetype == "image/png"
        assert app.test_client().get("/branding/secret").status_code == 404
    finally:
        for k in ("logo", "logo_light"):
            branding.remove(db, k)
        db.commit()


def test_setnetz_default_design(app, db):
    """Without own settings the Setnetz CI applies: bundled logos and fonts, no external sources."""
    make_user(db, "ci-admin", "admin")
    c = login(app, "ci-admin")
    page = c.get("/").text
    assert "/static/img/setnetz-logo-negativ.svg" in page
    login_page = app.test_client().get("/login").text
    assert "/static/img/setnetz-logo.svg" in login_page
    for path in ("/static/img/setnetz-logo.svg", "/static/img/setnetz-logo-negativ.svg",
                 "/static/fonts/ibm-plex-sans-latin-400-normal.woff2",
                 "/static/fonts/barlow-condensed-latin-700-normal.woff2"):
        assert app.test_client().get(path).status_code == 200, path
    css = app.test_client().get("/static/css/app.css").text
    assert "#1f6f94" in css and "#0e3a52" in css and "https://" not in css and "gradient(135deg" not in css
    try:
        settings.set(db, "brand.default_logo", False)
        db.commit()
        assert "setnetz-logo" not in c.get("/").text
        settings.set(db, "brand.font", "arial")
        assert "--font-head: var(--font)" in branding.css(db)
    finally:
        settings.set(db, "brand.default_logo", True)
        settings.set(db, "brand.font", settings.DEFAULTS["brand.font"])
        db.commit()
