/* Servermanager UI helpers (no external dependencies) */
(function () {
  "use strict";

  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  // ---------------------------------------------------------------- confirm
  document.addEventListener("submit", (e) => {
    const form = e.target;
    const msg = (e.submitter && e.submitter.dataset.confirm) || form.dataset.confirm;
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
      return;
    }
    if (e.submitter && !e.submitter.dataset.noDisable) {
      // prevent double submits
      setTimeout(() => { e.submitter.disabled = true; }, 0);
    }
  });

  // ---------------------------------------------------------------- colour pickers next to #RRGGBB fields
  document.querySelectorAll("input[type=color][data-color-for]").forEach((picker) => {
    const text = document.getElementById(picker.dataset.colorFor);
    if (!text) return;
    picker.addEventListener("input", () => { text.value = picker.value; });
    text.addEventListener("input", () => {
      const v = text.value.trim();
      const hex = v.startsWith("#") ? v : "#" + v;
      if (/^#[0-9a-fA-F]{6}$/.test(hex)) picker.value = hex.toLowerCase();
    });
  });

  // ---------------------------------------------------------------- dialogs (overlay)
  // <button data-dialog-open="#id" data-dialog-values='{"name": "..."}'> fills the fields of the same name and
  // the [data-dialog-text=key] elements of the <dialog>, then opens it modally.
  document.addEventListener("click", (e) => {
    const opener = e.target.closest("[data-dialog-open]");
    if (opener) {
      const dlg = document.querySelector(opener.dataset.dialogOpen);
      if (!dlg || typeof dlg.showModal !== "function") return;
      e.preventDefault();
      let values = {};
      try { values = JSON.parse(opener.dataset.dialogValues || "{}"); } catch (err) { values = {}; }
      Object.entries(values).forEach(([key, value]) => {
        dlg.querySelectorAll(`[name="${key}"]`).forEach((el) => { el.value = value; });
        dlg.querySelectorAll(`[data-dialog-text="${key}"]`).forEach((el) => { el.textContent = value; });
      });
      dlg.querySelectorAll("button").forEach((b) => { b.disabled = false; });
      dlg.showModal();
      const focus = dlg.querySelector("[autofocus]");
      if (focus) { focus.focus(); if (focus.select) focus.select(); }
      return;
    }
    if (e.target.closest("[data-dialog-close]")) {
      const dlg = e.target.closest("dialog");
      if (dlg) dlg.close();
      return;
    }
    // click on the backdrop closes the dialog
    if (e.target.tagName === "DIALOG" && e.target.classList.contains("modal")) {
      const r = e.target.getBoundingClientRect();
      if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) e.target.close();
    }
  });

  // ---------------------------------------------------------------- copy to clipboard
  function copyText(text, btn) {
    const done = () => {
      const old = btn.textContent;
      btn.textContent = "Kopiert ✓";
      setTimeout(() => { btn.textContent = old; }, 1500);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); done(); } finally { ta.remove(); }
    }
  }
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy]");
    if (!btn) return;
    e.preventDefault();
    const src = document.querySelector(btn.dataset.copy);
    if (src) copyText(src.value !== undefined && src.tagName !== "PRE" && src.tagName !== "CODE" ? src.value : src.innerText, btn);
  });

  // ---------------------------------------------------------------- select all / bulk bar
  function updateBulk(scope) {
    document.querySelectorAll("[data-bulk-count]").forEach((el) => {
      const sel = el.dataset.bulkCount;
      const n = document.querySelectorAll(sel + ":checked").length;
      el.textContent = n ? n + " ausgewählt" : "Keine Auswahl";
      const bar = el.closest(".bulkbar");
      if (bar) bar.querySelectorAll("button").forEach((b) => { b.disabled = n === 0; });
    });
  }
  document.addEventListener("change", (e) => {
    const all = e.target.closest("[data-check-all]");
    if (all) {
      document.querySelectorAll(all.dataset.checkAll).forEach((cb) => {
        const row = cb.closest("tr, label");
        if (!cb.disabled && (!row || row.offsetParent !== null)) cb.checked = all.checked;
      });
    }
    updateBulk();
  });
  updateBulk();

  // ---------------------------------------------------------------- auto submit selects
  document.addEventListener("change", (e) => {
    if (e.target.matches && e.target.matches("[data-autosubmit]") && e.target.form) e.target.form.submit();
  });

  // ---------------------------------------------------------------- list filter
  document.querySelectorAll("[data-filter-list]").forEach((input) => {
    input.addEventListener("input", () => {
      const q = input.value.toLowerCase();
      document.querySelectorAll(input.dataset.filterList).forEach((item) => {
        item.classList.toggle("hidden", q && !item.textContent.toLowerCase().includes(q));
      });
    });
  });

  // ---------------------------------------------------------------- show/hide by select value
  function applyShowFor() {
    document.querySelectorAll("[data-show-for]").forEach((el) => {
      const [name, values] = el.dataset.showFor.split("=");
      const ctrl = document.querySelector('[name="' + name + '"]:checked') || document.querySelector('select[name="' + name + '"]');
      const val = ctrl ? ctrl.value : "";
      el.classList.toggle("hidden", !values.split(",").includes(val));
    });
  }
  document.addEventListener("change", (e) => { if (e.target.name) applyShowFor(); });
  applyShowFor();

  // ---------------------------------------------------------------- async panels
  function loadPanel(el) {
    el.innerHTML = '<div class="empty"><span class="spinner"></span> Daten werden vom System geladen …</div>';
    fetch(el.dataset.load, { headers: { "X-Requested-With": "fetch" }, credentials: "same-origin" })
      .then((r) => r.text().then((t) => ({ ok: r.ok, status: r.status, text: t })))
      .then((r) => {
        el.innerHTML = r.ok ? r.text : '<div class="alert danger">Fehler beim Laden (HTTP ' + r.status + ")</div>";
        el.querySelectorAll("[data-filter-list]").forEach((i) => i.dispatchEvent(new Event("input")));
      })
      .catch((err) => { el.innerHTML = '<div class="alert danger">Fehler: ' + err + "</div>"; });
  }
  document.querySelectorAll("[data-load]").forEach(loadPanel);
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-reload]");
    if (!btn) return;
    e.preventDefault();
    const panel = btn.closest("[data-load]") || (btn.closest(".card") || document).querySelector("[data-load]");
    if (panel) loadPanel(panel);
  });
  // panel-internal filters are bound lazily
  document.addEventListener("input", (e) => {
    const input = e.target.closest("[data-filter-list]");
    if (!input || input.dataset.bound) return;
    const q = input.value.toLowerCase();
    document.querySelectorAll(input.dataset.filterList).forEach((item) => {
      item.classList.toggle("hidden", q && !item.textContent.toLowerCase().includes(q));
    });
  });

  // ---------------------------------------------------------------- job log
  const ANSI = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b[()][A-Z0-9]|\x1b[=>]/g;
  const log = document.getElementById("joblog");
  if (log) {
    const url = log.dataset.url;
    let offset = 0;
    let current = "";
    let curNode = document.createTextNode("");
    log.appendChild(curNode);
    let follow = true;
    log.addEventListener("scroll", () => {
      follow = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
    });
    const classify = (line) => {
      if (/^\[servermanager[^\]]*\] (✔|Job erfolgreich)/.test(line)) return "l-ok";
      if (/^\[servermanager[^\]]*\] (✘|FEHLER|Interner Fehler)/.test(line) || /^\[FEHLER\]|^E: /.test(line)) return "l-err";
      if (/^\[servermanager[^\]]*\] ── /.test(line) || /^==> /.test(line)) return "l-step";
      if (/^\[servermanager/.test(line)) return "l-sm";
      if (/^\[WARNUNG\]|^W: /.test(line)) return "l-warn";
      return "";
    };
    const appendLines = (lines) => {
      const frag = document.createDocumentFragment();
      let plain = "";
      lines.forEach((line) => {
        const cls = classify(line);
        if (cls) {
          if (plain) { frag.appendChild(document.createTextNode(plain)); plain = ""; }
          const span = document.createElement("span");
          span.className = cls;
          span.textContent = line + "\n";
          frag.appendChild(span);
        } else {
          plain += line + "\n";
        }
      });
      if (plain) frag.appendChild(document.createTextNode(plain));
      log.insertBefore(frag, curNode);
    };
    const feed = (text) => {
      text = text.replace(ANSI, "");
      const parts = text.split("\n");
      const done = [];
      parts.forEach((seg, i) => {
        if (seg.indexOf("\r") >= 0) {
          const segs = seg.split("\r").filter((s) => s !== "");
          current = segs.length ? segs[segs.length - 1] : current;
        } else {
          current += seg;
        }
        if (i < parts.length - 1) { done.push(current); current = ""; }
      });
      if (done.length) appendLines(done);
      curNode.textContent = current;
    };
    const badge = document.getElementById("job-status");
    const summary = document.getElementById("job-summary");
    const duration = document.getElementById("job-duration");
    const classes = { queued: "", running: "info running", success: "success", failed: "danger", cancelled: "warning", skipped: "" };
    const poll = () => {
      fetch(url + "?offset=" + offset, { credentials: "same-origin" })
        .then((r) => r.json())
        .then((d) => {
          if (d.text) feed(d.text);
          offset = d.offset;
          if (badge) {
            badge.className = "badge " + (classes[d.status] || "");
            badge.innerHTML = '<span class="dot"></span>' + d.status_label;
          }
          if (summary && d.summary) summary.textContent = d.summary;
          if (duration) duration.textContent = d.duration + " s";
          if (follow) log.scrollTop = log.scrollHeight;
          if (d.final) {
            document.querySelectorAll("[data-hide-when-final]").forEach((el) => el.classList.add("hidden"));
            if (!log.dataset.wasFinal) {
              log.dataset.wasFinal = "1";
              if (d.text) setTimeout(poll, 500);
            }
          } else {
            setTimeout(poll, d.text ? 600 : 1500);
          }
        })
        .catch(() => setTimeout(poll, 4000));
    };
    poll();
  }

  // ---------------------------------------------------------------- job status badges (reload when done)
  const watchers = document.querySelectorAll("[data-job-watch]");
  if (watchers.length) {
    const pending = new Set(Array.from(watchers).map((el) => el.dataset.jobWatch));
    const tick = () => {
      if (!pending.size) return;
      Promise.all(Array.from(pending).map((id) =>
        fetch("/jobs/" + id + "/log?offset=999999999999", { credentials: "same-origin" })
          .then((r) => r.json())
          .then((d) => {
            document.querySelectorAll('[data-job-watch="' + id + '"]').forEach((el) => {
              el.className = "badge " + ({ running: "info running", success: "success", failed: "danger", cancelled: "warning" }[d.status] || "");
              el.innerHTML = '<span class="dot"></span>' + d.status_label;
            });
            if (d.final) pending.delete(id);
          }).catch(() => {})
      )).then(() => {
        if (pending.size) setTimeout(tick, 3000);
        else if (document.body.dataset.reloadOnJobs) setTimeout(() => window.location.reload(), 800);
      });
    };
    setTimeout(tick, 1500);
  }

  // ---------------------------------------------------------------- auto refresh
  const ar = document.body.dataset.autorefresh;
  if (ar) {
    setTimeout(() => {
      if (!document.querySelector("input:focus, textarea:focus, select:focus")) window.location.reload();
    }, parseInt(ar, 10) * 1000);
  }

  // ---------------------------------------------------------------- wait for restart (update/restore)
  const waiter = document.getElementById("restart-wait");
  if (waiter) {
    const next = waiter.dataset.next || "/";
    let seenDown = false;
    const started = Date.now();
    const check = () => {
      fetch("/healthz", { cache: "no-store" })
        .then((r) => {
          if (r.ok && (seenDown || Date.now() - started > 20000)) window.location.href = next;
          else setTimeout(check, 2000);
        })
        .catch(() => { seenDown = true; setTimeout(check, 2000); });
      const logEl = document.getElementById("update-log");
      if (logEl && waiter.dataset.log) {
        fetch(waiter.dataset.log, { credentials: "same-origin" }).then((r) => r.json())
          .then((d) => { logEl.textContent = d.log; logEl.scrollTop = logEl.scrollHeight; }).catch(() => {});
      }
    };
    setTimeout(check, 3000);
  }

  // ---------------------------------------------------------------- self-update progress
  const up = document.getElementById("update-progress");
  if (up) {
    const $ = (id) => document.getElementById(id);
    const t0 = Date.now();
    let offlineSince = 0, sawOffline = false, finished = false, lastLog = null;
    const fmt = (s) => (s >= 60 ? Math.floor(s / 60) + " min " : "") + (s % 60) + " s";
    const render = (st, version, log) => {
      const total = st.total || 7;
      const state = st.state;
      let done = 0;
      if (state === "success" || state === "uptodate") done = total;
      else if (state === "running") done = Math.max(0, st.step - 1);
      else if (state === "rollback" || state === "failed" || state === "stale") done = Math.max(0, st.step - 1);
      // the new version answering means the restart worked, even with an old status format
      const upgraded = (version && version !== up.dataset.version) || sawOffline;
      const pct = state === "running" ? Math.round((done + 0.5) / total * 100) : Math.round(done / total * 100);
      $("up-bar").style.width = pct + "%";
      $("up-pct").textContent = pct + " %";
      const bar = $("up-bar").parentElement;
      bar.classList.toggle("done", state === "success" || state === "uptodate");
      bar.classList.toggle("failed", ["failed", "rollback", "stale"].includes(state));
      bar.classList.toggle("active", state === "running" || state === "starting" || state === "unknown");
      $("up-steps").querySelectorAll("li").forEach((li) => {
        const n = Number(li.dataset.step);
        li.className = n <= done ? "done"
          : (n === st.step && state === "running") ? "current"
          : (n === st.step && ["failed", "rollback", "stale"].includes(state)) ? "failed" : "";
      });
      let title = st.label || "";
      if (state === "starting" || state === "unknown") title = "Update wird gestartet …";
      if (state === "stale") title = "Keine Rückmeldung mehr vom Update";
      $("up-title").textContent = title;
      if (log !== undefined && log !== lastLog) {
        lastLog = log;
        const el = $("up-log");
        el.textContent = log;
        el.scrollTop = el.scrollHeight;
      }
      if (state === "success" || (state === "unknown" && upgraded)) {
        finished = true;
        $("up-success").hidden = false;
        $("up-success-text").textContent = "Version " + (version || "") + (st.new ? " (" + st.new + ")" : "") + " ist aktiv.";
        $("up-bar").style.width = "100%"; $("up-pct").textContent = "100 %";
        bar.classList.add("done"); bar.classList.remove("active");
        setTimeout(() => { window.location.href = up.dataset.next; }, 8000);
      } else if (state === "uptodate") {
        finished = true; $("up-uptodate").hidden = false;
      } else if (state === "failed" || state === "stale") {
        finished = true;
        $("up-failed").hidden = false;
        $("up-failed-text").textContent = state === "stale"
          ? "Seit über 30 Minuten keine Rückmeldung – Protokoll prüfen." : (st.label || "");
        $("up-log-box").open = true;
      }
    };
    const poll = () => {
      $("up-elapsed").textContent = "(" + fmt(Math.round((Date.now() - t0) / 1000)) + ")";
      fetch(up.dataset.status, { credentials: "same-origin", cache: "no-store" })
        .then((r) => {
          if (r.redirected && r.url.includes("/login")) { window.location.href = up.dataset.next; throw new Error("login"); }
          if (!r.ok || !(r.headers.get("content-type") || "").includes("json")) throw new Error(); return r.json(); })
        .then((d) => {
          offlineSince = 0; $("up-offline").hidden = true;
          render(d.status, d.version, d.log);
          if (!finished) setTimeout(poll, 1500);
        })
        .catch(() => {
          // web service restarting (or login needed after the restart)
          if (!offlineSince) offlineSince = Date.now();
          sawOffline = true;
          $("up-offline").hidden = false;
          setTimeout(poll, 2000);
        });
    };
    render({ state: up.dataset.state, step: 0, total: 7, label: "" });
    poll();
  }

  // expose for inline use
  window.SM = { csrf };

  // ---------------------------------------------------------------- chart crosshair + tooltip
  document.querySelectorAll("[data-chart] svg[data-points]").forEach((svg) => {
    let points, labels, classes;
    try {
      points = JSON.parse(svg.dataset.points);
      labels = JSON.parse(svg.dataset.labels);
      classes = JSON.parse(svg.dataset.classes);
    } catch (err) { return; }
    const box = svg.parentElement;
    const tip = box.querySelector(".chart-tip");
    const cross = svg.querySelector(".crosshair");
    const hit = svg.querySelector(".hit");
    if (!points.length || !tip || !cross || !hit) return;
    const vb = svg.viewBox.baseVal;
    function show(evt) {
      const rect = svg.getBoundingClientRect();
      const x = (evt.clientX - rect.left) / rect.width * vb.width;
      let best = points[0];
      points.forEach((p) => { if (Math.abs(p.x - x) < Math.abs(best.x - x)) best = p; });
      cross.setAttribute("x1", best.x);
      cross.setAttribute("x2", best.x);
      cross.classList.remove("hidden");
      tip.textContent = "";
      const t = document.createElement("div");
      t.className = "t";
      t.textContent = best.t;
      tip.appendChild(t);
      best.v.forEach((v, i) => {
        const row = document.createElement("div");
        row.className = "row";
        const key = document.createElement("i");
        key.className = classes[i] || "";
        const val = document.createElement("strong");
        val.textContent = v;
        const lab = document.createElement("span");
        lab.textContent = labels[i] || "";
        row.append(key, val, lab);
        tip.appendChild(row);
      });
      tip.classList.remove("hidden");
      const px = best.x / vb.width * rect.width;
      const left = px + 12 + tip.offsetWidth > rect.width ? px - tip.offsetWidth - 12 : px + 12;
      tip.style.left = Math.max(0, left) + "px";
    }
    function hide() { cross.classList.add("hidden"); tip.classList.add("hidden"); }
    hit.addEventListener("pointermove", show);
    hit.addEventListener("pointerleave", hide);
  });
})();
