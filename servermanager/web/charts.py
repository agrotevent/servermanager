"""Small server-side SVG line charts (Proxmox RRD data) - no JavaScript libraries needed.

One measure per chart (never two y-scales). The template renders the SVG,
a legend for >= 2 series, direct end labels and a table view; app.js adds the
crosshair tooltip from the ``points`` data.
"""
from __future__ import annotations

import math
from datetime import datetime
from typing import Callable, Optional

W, H = 640, 190
PAD_L, PAD_R, PAD_T, PAD_B = 52, 64, 12, 26


def fmt_pct(v: float) -> str:
    return f"{v:.0f} %" if v >= 10 else f"{v:.1f} %"


def fmt_bytes(v: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(v) < 1024 or unit == "TB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"


def fmt_rate(v: float) -> str:
    return fmt_bytes(v) + "/s"


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def line_chart(rows: list[dict], series: list[tuple[str, str, Callable[[dict], Optional[float]]]],
               fmt: Callable[[float], str], y_max: Optional[float] = None, timeframe: str = "hour",
               tz=None) -> Optional[dict]:
    """rows: RRD rows (with 'time'); series: (label, css class, value getter)."""
    rows = [r for r in rows if r.get("time")]
    if len(rows) < 2:
        return None
    rows.sort(key=lambda r: r["time"])
    t0, t1 = rows[0]["time"], rows[-1]["time"]
    span = max(1, t1 - t0)
    values = [[get(r) for r in rows] for _l, _c, get in series]
    peak = max((v for vs in values for v in vs if v is not None), default=0)
    top = y_max if y_max is not None else _nice_max(peak * 1.1)
    iw, ih = W - PAD_L - PAD_R, H - PAD_T - PAD_B

    def x(t: float) -> float:
        return PAD_L + (t - t0) / span * iw

    def y(v: float) -> float:
        return PAD_T + ih - min(v, top) / top * ih

    out_series = []
    for (label, cls, _get), vs in zip(series, values):
        path, pen = [], False
        last = None
        for r, v in zip(rows, vs):
            if v is None:
                pen = False
                continue
            path.append(f"{'L' if pen else 'M'}{x(r['time']):.1f},{y(v):.1f}")
            pen = True
            last = (x(r["time"]), y(v), v)
        out_series.append({"label": label, "cls": cls, "path": " ".join(path),
                           "last": {"x": last[0], "y": last[1], "text": fmt(last[2])} if last else None})
    # avoid colliding end labels
    ends = sorted([s for s in out_series if s["last"]], key=lambda s: s["last"]["y"])
    for a, b in zip(ends, ends[1:]):
        if b["last"]["y"] - a["last"]["y"] < 13:
            b["last"]["y"] = a["last"]["y"] + 13
    time_fmt = "%H:%M" if timeframe in ("hour", "day") else ("%d.%m." if timeframe != "year" else "%m/%y")
    xticks = []
    for i in range(5):
        t = t0 + span * i / 4
        xticks.append({"x": round(x(t), 1), "label": datetime.fromtimestamp(t, tz).strftime(time_fmt)})
    yticks = [{"y": round(y(top * i / 4), 1), "label": fmt(top * i / 4)} for i in range(5)]
    tip_fmt = "%d.%m. %H:%M"
    points = [{"x": round(x(r["time"]), 1), "t": datetime.fromtimestamp(r["time"], tz).strftime(tip_fmt),
               "v": [fmt(v) if v is not None else "–" for v in vs]}
              for r, *vs in zip(rows, *values)]
    table = [{"t": p["t"], "v": p["v"]} for p in points[::max(1, len(points) // 24)]]
    return {"w": W, "h": H, "plot": {"x0": PAD_L, "x1": W - PAD_R, "y0": PAD_T, "y1": H - PAD_B},
            "series": out_series, "labels": [s[0] for s in series], "classes": [s[1] for s in series],
            "xticks": xticks, "yticks": yticks, "points": points, "table": table}


def rrd_charts(rows: list[dict], timeframe: str, gtype: str = "lxc", tz=None) -> list[dict]:
    charts = []
    cpu = line_chart(rows, [("CPU", "s1", lambda r: (r["cpu"] * 100) if r.get("cpu") is not None else None)],
                     fmt_pct, y_max=100, timeframe=timeframe, tz=tz)
    if cpu:
        charts.append({"title": "CPU-Auslastung", **cpu})
    maxmem = max((r.get("maxmem") or 0 for r in rows), default=0)
    mem = line_chart(rows, [("RAM belegt", "s1", lambda r: r.get("mem"))], fmt_bytes,
                     y_max=float(maxmem) if maxmem else None, timeframe=timeframe, tz=tz)
    if mem:
        charts.append({"title": "Arbeitsspeicher" + (f" (von {fmt_bytes(maxmem)})" if maxmem else ""), **mem})
    net = line_chart(rows, [("Eingehend", "s1", lambda r: r.get("netin")), ("Ausgehend", "s2", lambda r: r.get("netout"))],
                     fmt_rate, timeframe=timeframe, tz=tz)
    if net:
        charts.append({"title": "Netzwerk", **net})
    if gtype == "lxc":
        maxdisk = max((r.get("maxdisk") or 0 for r in rows), default=0)
        disk = line_chart(rows, [("Belegt", "s1", lambda r: r.get("disk"))], fmt_bytes,
                          y_max=float(maxdisk) if maxdisk else None, timeframe=timeframe, tz=tz)
        if disk:
            charts.append({"title": "Root-Dateisystem" + (f" (von {fmt_bytes(maxdisk)})" if maxdisk else ""), **disk})
    return charts
