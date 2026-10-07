"""Corporate design: colours, logo and font of the web interface (Einstellungen → Erscheinungsbild).

Colours become CSS variables (hover, light and dark variants are derived); logo and font are stored in the
database (so they are part of the servermanager backups) and served by the application itself - the CSP
only allows own sources.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Optional

from sqlalchemy.orm import Session

from . import settings

HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
LOGO_TYPES = {"image/svg+xml": "svg", "image/png": "png", "image/webp": "webp", "image/jpeg": "jpg"}
FONT_TYPES = {"font/woff2": "woff2", "font/woff": "woff", "font/ttf": "ttf", "font/otf": "otf"}
MAX_LOGO = 512 * 1024
MAX_FONT = 2 * 1024 * 1024
FONT_STACKS = {
    "setnetz": '"IBM Plex Sans", system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif',
    "system": 'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    "arial": 'Arial, "Helvetica Neue", Helvetica, sans-serif',
    "verdana": "Verdana, Geneva, sans-serif",
    "georgia": "Georgia, \"Times New Roman\", serif",
}
FONT_LABELS = {"setnetz": "Setnetz: IBM Plex Sans, Überschriften Barlow Condensed (Standard)",
               "system": "Systemschrift", "arial": "Arial / Helvetica", "verdana": "Verdana",
               "georgia": "Georgia (Serifen)", "custom": "Eigene Schriftdatei"}


class BrandError(ValueError):
    pass


# ----------------------------------------------------------------------------- colours
def _rgb(hex_: str) -> tuple[int, int, int]:
    h = hex_.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _hex(rgb) -> str:
    return "#" + "".join(f"{max(0, min(255, round(c))):02x}" for c in rgb)


def mix(a: str, b: str, t: float) -> str:
    """t=0: a, t=1: b."""
    ra, rb = _rgb(a), _rgb(b)
    return _hex(tuple(x + (y - x) * t for x, y in zip(ra, rb)))


def luminance(hex_: str) -> float:
    def ch(c: int) -> float:
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(c) for c in _rgb(hex_))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def on_color(bg: str) -> str:
    """Readable text colour on ``bg``."""
    return "#ffffff" if contrast(bg, "#ffffff") >= contrast(bg, "#0f172a") else "#0f172a"


def check_hex(value: str, label: str) -> str:
    value = (value or "").strip()
    if value and not value.startswith("#"):
        value = "#" + value
    if not HEX_RE.match(value):
        raise BrandError(f"{label}: Farbe als #RRGGBB angeben (z. B. #e30613)")
    return value.lower()


def css(db: Session) -> str:
    """CSS variables overriding the default theme ('' when nothing is configured)."""
    primary = settings.get(db, "brand.primary") or ""
    sidebar = settings.get(db, "brand.sidebar") or ""
    accent = settings.get(db, "brand.accent") or ""
    font = settings.get(db, "brand.font") or "setnetz"
    light, dark, extra = [], [], []
    if HEX_RE.match(primary):
        on = on_color(primary)
        light += [f"--primary: {primary}", f"--primary-hover: {mix(primary, '#000000', .15)}",
                  f"--primary-soft: {mix(primary, '#ffffff', .85)}", f"--on-primary: {on}",
                  f"--brand-a: {primary}", f"--login-a: {mix(primary, '#000000', .35)}"]
        dp = mix(primary, "#ffffff", .2) if luminance(primary) < .2 else primary
        dark += [f"--primary: {dp}", f"--primary-hover: {mix(dp, '#ffffff', .15)}",
                 f"--primary-soft: {dp}40", f"--on-primary: {on_color(dp)}"]
        if not HEX_RE.match(accent):
            light.append(f"--brand-b: {mix(primary, '#ffffff', .35)}")
    if HEX_RE.match(accent):
        light.append(f"--brand-b: {accent}")
    if HEX_RE.match(sidebar):
        text = on_color(sidebar)
        darkbg = text == "#ffffff"
        light += [f"--sidebar: {sidebar}", f"--login-b: {sidebar if darkbg else mix(sidebar, '#000000', .6)}",
                  f"--sidebar-text: {mix(text, sidebar, .22)}", f"--sidebar-strong: {text}",
                  f"--sidebar-muted: {mix(text, sidebar, .5)}",
                  f"--sidebar-active: {mix(sidebar, '#ffffff' if darkbg else '#000000', .1)}",
                  f"--sidebar-count: {mix(sidebar, '#ffffff' if darkbg else '#000000', .2)}"]
        dark += [f"--sidebar: {mix(sidebar, '#000000', .35) if darkbg else sidebar}"]
    if font == "custom" and settings.get(db, "brand.font_data"):
        extra.append("@font-face { font-family: \"SM Brand\"; src: url(\"/branding/font?v=%s\"); "
                     "font-display: swap; }" % asset_version(db, "font"))
        light += [f"--font: \"SM Brand\", {FONT_STACKS['system']}", "--font-head: var(--font)"]
    elif font in FONT_STACKS and font != "setnetz":
        light += [f"--font: {FONT_STACKS[font]}", "--font-head: var(--font)"]
    if not light:
        return ""
    out = extra + [":root { " + "; ".join(light) + "; }"]
    if dark:
        out.append("@media (prefers-color-scheme: dark) { :root { " + "; ".join(dark) + "; } }")
    return "\n".join(out)


# ----------------------------------------------------------------------------- files
def _sniff(data: bytes, kind: str) -> Optional[str]:
    if kind == "logo":
        head = data[:512].lstrip().lower()
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if data.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return "image/webp"
        if head.startswith(b"<?xml") or head.startswith(b"<svg") or b"<svg" in data[:2048].lower():
            return "image/svg+xml"
        return None
    if data[:4] == b"wOF2":
        return "font/woff2"
    if data[:4] == b"wOFF":
        return "font/woff"
    if data[:4] in (b"\x00\x01\x00\x00", b"true"):
        return "font/ttf"
    if data[:4] == b"OTTO":
        return "font/otf"
    return None


KINDS = ("logo", "logo_light", "font")


def _is_logo(kind: str) -> bool:
    return kind in ("logo", "logo_light")


def store(db: Session, kind: str, data: bytes) -> str:
    """Validate and store a logo or font file; returns its media type."""
    if kind not in KINDS:
        raise BrandError("Unbekannte Datei")
    limit = MAX_LOGO if _is_logo(kind) else MAX_FONT
    if not data:
        raise BrandError("Keine Datei ausgewählt")
    if len(data) > limit:
        raise BrandError(f"Datei zu groß (höchstens {limit // 1024} KB)")
    mime = _sniff(data, "logo" if _is_logo(kind) else "font")
    if mime is None:
        raise BrandError("Logo als SVG, PNG, WebP oder JPEG hochladen" if _is_logo(kind)
                         else "Schrift als WOFF2, WOFF, TTF oder OTF hochladen")
    if mime == "image/svg+xml":
        text = data.decode("utf-8", "replace").lower()
        if re.search(r"<script|\bon[a-z]+\s*=|javascript:|<foreignobject|<iframe|<embed|<object", text):
            raise BrandError("Das SVG enthält Skripte oder eingebettete Inhalte – bitte ein reines Grafik-SVG")
    settings.set(db, f"brand.{kind}_data", base64.b64encode(data).decode())
    settings.set(db, f"brand.{kind}_type", mime)
    return mime


def remove(db: Session, kind: str) -> None:
    settings.set(db, f"brand.{kind}_data", "")
    settings.set(db, f"brand.{kind}_type", "")


def load(db: Session, kind: str) -> Optional[tuple[bytes, str]]:
    raw = settings.get(db, f"brand.{kind}_data") or ""
    mime = settings.get(db, f"brand.{kind}_type") or ""
    if not raw or mime not in (LOGO_TYPES if _is_logo(kind) else FONT_TYPES):
        return None
    return base64.b64decode(raw), mime


def asset_version(db: Session, kind: str) -> str:
    return hashlib.sha256((settings.get(db, f"brand.{kind}_data") or "").encode()).hexdigest()[:12]
