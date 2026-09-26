"""Online help: renders the Markdown documentation from docs/."""
from __future__ import annotations

import html
import re
import subprocess
from functools import lru_cache
from pathlib import Path

import markdown
from flask import Blueprint, abort, render_template, request, url_for
from markupsafe import Markup

from ..auth import login_required

bp = Blueprint("help", __name__, url_prefix="/hilfe")
DOCS_DIR = Path(__file__).resolve().parents[3] / "docs"

# (slug, title, section) - order of the navigation. New pages must be added here.
PAGES: list[tuple[str, str, str]] = [
    ("index", "Überblick", "Einstieg"),
    ("erste-schritte", "Erste Schritte", "Einstieg"),
    ("oberflaeche", "Bedienung der Oberfläche", "Einstieg"),
    ("systeme", "Systeme hinzufügen", "Verwaltung"),
    ("module", "Funktionen je Systemtyp", "Verwaltung"),
    ("updates-wartung", "Update-Übersicht & Wartungsplaner", "Verwaltung"),
    ("wireguard", "WireGuard & MikroTik", "Verwaltung"),
    ("benutzer", "Benutzer und Rechte", "Verwaltung"),
    ("bestand", "Bestand übernehmen & Optimierungen", "Infrastruktur"),
    ("proxmox", "Proxmox VE über die API", "Infrastruktur"),
    ("routeros", "RouterOS (CHR) über die API", "Infrastruktur"),
    ("pangolin", "Pangolin: Dienste veröffentlichen", "Infrastruktur"),
    ("backup", "Backup und Restore", "Betrieb"),
    ("servermanager-update", "Update des Servermanagers", "Betrieb"),
    ("installation", "Installation", "Betrieb"),
    ("cli", "Kommandozeile", "Betrieb"),
    ("sicherheit", "Sicherheit", "Betrieb"),
    ("dateien", "Dateien und Pfade", "Betrieb"),
    ("fehlerbehebung", "Fehlerbehebung", "Betrieb"),
    ("entwicklung", "Entwicklung", "Betrieb"),
    ("changelog", "Änderungsprotokoll", "Betrieb"),
]
TITLES = {slug: title for slug, title, _ in PAGES}
LINK_RE = re.compile(r'href="([a-z0-9-]+)\.md(#[^"]*)?"')


def _path(slug: str) -> Path:
    if slug not in TITLES:
        abort(404)
    return DOCS_DIR / f"{slug}.md"


@lru_cache(maxsize=64)
def _render(slug: str, mtime: float) -> tuple[str, str]:
    """Return (html, toc_html) - cached per file modification time."""
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                          extension_configs={"toc": {"toc_depth": "2-3"}})
    body = md.convert(_path(slug).read_text(encoding="utf-8"))
    body = LINK_RE.sub(lambda m: f'href="{url_for("help.page", slug=m.group(1))}{m.group(2) or ""}"', body)
    return body, md.toc


@lru_cache(maxsize=64)
def _last_change(slug: str, mtime: float) -> str:
    try:
        res = subprocess.run(["git", "-C", str(DOCS_DIR.parent), "log", "-1", "--format=%cd", "--date=format:%d.%m.%Y",
                              "--", f"docs/{slug}.md"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    from datetime import datetime
    return datetime.fromtimestamp(mtime).strftime("%d.%m.%Y")


def _nav() -> list[tuple[str, list[tuple[str, str]]]]:
    sections: dict[str, list[tuple[str, str]]] = {}
    for slug, title, section in PAGES:
        sections.setdefault(section, []).append((slug, title))
    return list(sections.items())


@bp.get("/")
@bp.get("/<slug>")
@login_required
def page(slug: str = "index"):
    path = _path(slug)
    if not path.exists():
        abort(404)
    mtime = path.stat().st_mtime
    body, toc = _render(slug, mtime)
    idx = [s for s, _, _ in PAGES].index(slug)
    prev_page = PAGES[idx - 1] if idx > 0 else None
    next_page = PAGES[idx + 1] if idx + 1 < len(PAGES) else None
    return render_template("help/page.html", slug=slug, title=TITLES[slug], body=Markup(body), toc=Markup(toc),
                           nav=_nav(), updated=_last_change(slug, mtime), prev_page=prev_page, next_page=next_page)


@bp.get("/suche")
@login_required
def search():
    q = request.args.get("q", "").strip()
    results = []
    if len(q) >= 2:
        needle = q.lower()
        for slug, title, _ in PAGES:
            path = DOCS_DIR / f"{slug}.md"
            if not path.exists():
                continue
            hits = []
            for line in path.read_text(encoding="utf-8").splitlines():
                if needle in line.lower():
                    text = re.sub(r"[`*#|>\[\]]", "", line).strip()
                    if text:
                        pos = text.lower().find(needle)
                        snippet = html.escape(text[max(0, pos - 60): pos + 90])
                        hits.append(Markup(re.sub(re.escape(html.escape(q)), lambda m: f"<mark>{m.group(0)}</mark>",
                                                  snippet, flags=re.I)))
            if hits or needle in title.lower():
                results.append({"slug": slug, "title": title, "hits": hits[:4], "count": len(hits)})
        results.sort(key=lambda r: -r["count"])
    return render_template("help/search.html", q=q, results=results, nav=_nav(), slug="")
