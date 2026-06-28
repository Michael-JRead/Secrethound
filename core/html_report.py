"""html_report.py - self-contained HTML export of findings + scoreboard + chains.

Pure-stdlib (no jinja, no jsdeps); produces a single .html file you can email,
attach to a report, or open offline. Designed to mirror the CLI layout: KPI
panel + scoreboard table + ATTACK PATH ranked list + per-category findings
table, all with severity-color-coded rows, sortable tables (vanilla JS),
collapsible per-category sections, and a search box.
"""
import html
import json
import os


_CSS = """
body { background:#0f1117; color:#dfe2ea; font-family:'JetBrains Mono','Menlo','Consolas',monospace; margin:0; padding:0; font-size:13px; }
.wrap { max-width:1400px; margin:0 auto; padding:24px; }
h1 { color:#9be7b6; font-weight:700; margin:0 0 6px; letter-spacing:-0.5px; }
.tag { color:#5f6b80; font-size:11px; letter-spacing:0.5px; text-transform:uppercase; }
.panel { background:#161922; border:1px solid #232838; border-radius:10px; padding:18px; margin:18px 0; }
.kpi { display:flex; gap:18px; flex-wrap:wrap; }
.kpi .k { background:#0f1117; border:1px solid #1c2030; border-radius:8px; padding:10px 14px; min-width:120px; }
.kpi .k .n { font-size:22px; font-weight:700; }
.kpi .k .lbl { font-size:10px; color:#7a8094; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px; }
.sev-CRITICAL { color:#ff6b6b; }   .row-CRITICAL { border-left:3px solid #ff6b6b; }
.sev-HIGH     { color:#ff9e4c; }   .row-HIGH     { border-left:3px solid #ff9e4c; }
.sev-MEDIUM   { color:#ffd866; }   .row-MEDIUM   { border-left:3px solid #ffd866; }
.sev-LOW      { color:#60d6c2; }   .row-LOW      { border-left:3px solid #60d6c2; }
.sev-INFO     { color:#8eb3ff; }   .row-INFO     { border-left:3px solid #8eb3ff; }
table { width:100%; border-collapse:separate; border-spacing:0; }
th { text-align:left; padding:8px 10px; color:#7a8094; font-weight:500; font-size:10px; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid #1c2030; cursor:pointer; user-select:none; background:#10131a; }
th:hover { background:#161b25; }
td { padding:8px 10px; border-bottom:1px solid #14171f; vertical-align:top; font-size:12px; }
tr:hover td { background:#1a1f2c; }
.cat-h { display:flex; justify-content:space-between; align-items:center; background:#10131a; padding:10px 14px; border-radius:6px; cursor:pointer; margin-top:14px; }
.cat-h h2 { margin:0; font-size:13px; color:#dfe2ea; font-weight:600; }
.cat-h .meta { color:#7a8094; font-size:11px; }
.cat-body { display:block; }
.cat-body.hidden { display:none; }
.path { color:#8eb3ff; }
.line { color:#7a8094; font-size:10px; }
.detail { white-space:pre-wrap; word-break:break-word; max-width:520px; }
.hint { color:#7a8094; font-style:italic; font-size:11px; margin-top:3px; max-width:520px; word-break:break-word; }
.search { width:100%; padding:10px 12px; background:#0f1117; border:1px solid #232838; border-radius:6px; color:#dfe2ea; font-family:inherit; margin-bottom:6px; }
.attackpath { margin:0; padding:0; list-style:none; }
.attackpath li { padding:10px 12px; margin-bottom:8px; background:#10131a; border-radius:6px; border-left:3px solid #ff6b6b; }
.cmd { background:#0a0c12; padding:6px 8px; border-radius:4px; color:#9be7b6; font-size:11px; margin:4px 0; display:block; word-break:break-all; white-space:pre-wrap; }
.note { color:#7a8094; font-size:11px; }
.scoreboard td .ribbon { letter-spacing:1px; color:#60d6c2; }
.scoreboard td.dim { color:#5f6b80; }
.footer { margin-top:40px; padding-top:14px; border-top:1px solid #1c2030; color:#5f6b80; font-size:10px; }
.pill { display:inline-block; padding:2px 7px; border-radius:11px; font-size:10px; text-transform:uppercase; letter-spacing:1px; }
.pill.adm { background:#3a0d0d; color:#ff6b6b; }
.pill.crd { background:#0d2a3a; color:#8eb3ff; }
"""

_JS = """
function sortTable(table, col) {
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const dir = table.dataset.sortdir === 'asc' ? 'desc' : 'asc';
  const cmp = (a, b) => {
    const av = a.cells[col].dataset.sort || a.cells[col].textContent;
    const bv = b.cells[col].dataset.sort || b.cells[col].textContent;
    const an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return dir === 'asc' ? an - bn : bn - an;
    return dir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
  };
  rows.sort(cmp).forEach(r => tbody.appendChild(r));
  table.dataset.sortdir = dir;
}
function bindSort() {
  document.querySelectorAll('table.sortable').forEach(t => {
    Array.from(t.tHead.rows[0].cells).forEach((th, i) => {
      th.addEventListener('click', () => sortTable(t, i));
    });
  });
}
function bindToggles() {
  document.querySelectorAll('.cat-h').forEach(h => {
    h.addEventListener('click', () => {
      const body = h.nextElementSibling;
      if (body) body.classList.toggle('hidden');
    });
  });
}
function bindSearch() {
  const s = document.getElementById('search');
  if (!s) return;
  s.addEventListener('input', () => {
    const q = s.value.toLowerCase();
    document.querySelectorAll('tr.f-row').forEach(r => {
      r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}
window.addEventListener('DOMContentLoaded', () => { bindSort(); bindToggles(); bindSearch(); });
"""


def _e(s):
    return html.escape(str(s) if s is not None else "")


def _kpi(label, value, color=""):
    return (f'<div class="k"><div class="lbl">{_e(label)}</div>'
            f'<div class="n {_e(color)}">{_e(value)}</div></div>')


def write_html(report, chains, store, out_path):
    findings = report._dedup()
    stats = report.stats or {}
    n_total = len(findings)
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    n_chains = len(chains or [])

    # Build by-category groups
    from core.report import CAT_ORDER, SEV_RANK
    findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["category"]))
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f["category"], []).append(f)
    cats = [c for c in CAT_ORDER if c in by_cat] + [c for c in by_cat if c not in CAT_ORDER]

    # Scoreboard per-machine state
    mstate = report._machine_state(chains or [], store)
    scoreboard_rows = []
    for name, d in sorted(mstate.items(),
                          key=lambda kv: (-kv[1]["stage"],
                                          -(kv[1]["best"].score if kv[1]["best"] else 0),
                                          -kv[1]["creds"] - kv[1]["hashes"])):
        stage = report.STAGES[d["stage"]]
        pill = ""
        if d["stage"] >= 3:
            pill = '<span class="pill adm">admin</span>'
        elif d["stage"] >= 2:
            pill = '<span class="pill crd">creds</span>'
        ribbon = "▰" * (d["stage"] + 1) + "▱" * (len(report.STAGES) - d["stage"] - 1)
        best = d["best"].summary if d["best"] else "—"
        scoreboard_rows.append(
            f'<tr><td><b>{_e(name)}</b> {pill}</td>'
            f'<td class="sev-{stage.upper() if stage=="admin" else "INFO"}">{_e(stage)}</td>'
            f'<td class="ribbon">{ribbon}</td>'
            f'<td>{d["creds"] or "·"}</td>'
            f'<td>{d["hashes"] or "·"}</td>'
            f'<td class="dim">{_e(best)}</td></tr>'
        )

    # ATTACK PATH list
    ap_html = ""
    if chains:
        ap_html = '<ul class="attackpath">'
        for c in chains[:10]:
            cmds_html = ""
            for cmd in c.commands[:2]:
                cmds_html += f'<code class="cmd">{_e(cmd)}</code>'
            count_pill = (f'<span class="pill crd">×{c.count}</span>' if c.count > 1 else "")
            ap_html += (
                f'<li><b>[{_e(c.rule)}] {_e(c.label)}</b> {count_pill}<br>'
                f'<span class="note">score {c.score} — {_e(c.summary)}</span>'
                f'{cmds_html}</li>'
            )
        ap_html += "</ul>"

    # Findings per-category tables
    cat_html = ""
    for cat in cats:
        items = by_cat[cat]
        cat_html += f'<div class="cat-h"><h2>{_e(cat)}</h2><span class="meta">{len(items)} finding(s) — click to collapse</span></div>'
        cat_html += '<div class="cat-body"><table class="sortable"><thead><tr>'
        cat_html += '<th>Sev</th><th>File</th><th>Line</th><th>Detail</th><th>Hint</th></tr></thead><tbody>'
        for f in items:
            loc = report._rel(f["file"])
            cat_html += (
                f'<tr class="f-row row-{f["severity"]}" data-sev="{f["severity"]}">'
                f'<td class="sev-{f["severity"]}"><b>{_e(f["severity"])}</b></td>'
                f'<td class="path">{_e(loc)}</td>'
                f'<td class="line">{_e(f["line"] or "")}</td>'
                f'<td class="detail">{_e(f["detail"])}</td>'
                f'<td class="hint">{_e(f["hint"] or "")}</td>'
                f'</tr>'
            )
        cat_html += '</tbody></table></div>'

    sev_kpis = "".join([
        _kpi("CRITICAL", by_sev.get("CRITICAL", 0), "sev-CRITICAL"),
        _kpi("HIGH",     by_sev.get("HIGH", 0),     "sev-HIGH"),
        _kpi("MEDIUM",   by_sev.get("MEDIUM", 0),   "sev-MEDIUM"),
        _kpi("LOW",      by_sev.get("LOW", 0),      "sev-LOW"),
        _kpi("INFO",     by_sev.get("INFO", 0),     "sev-INFO"),
        _kpi("Chains",   n_chains, ""),
        _kpi("Total",    n_total,  ""),
        _kpi("Files scanned", stats.get("scanned", "?"), ""),
        _kpi("Elapsed", f"{stats.get('elapsed', 0):.1f}s" if stats.get("elapsed") is not None else "—", ""),
    ])

    body = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>secrethound — loot triage report</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>secrethound</h1>
<div class="tag">offline OSCP+/red-team loot triage · {_e(report.root)}</div>

<div class="panel"><div class="kpi">{sev_kpis}</div></div>

<div class="panel"><h2 style="margin-top:0">Engagement Scoreboard</h2>
<table class="sortable scoreboard"><thead><tr>
<th>Host</th><th>Stage</th><th>Progress</th><th>Creds</th><th>Hashes</th><th>Best Next Move</th>
</tr></thead><tbody>{''.join(scoreboard_rows) or '<tr><td colspan="6" class="dim">no machines profiled</td></tr>'}</tbody></table></div>

<div class="panel"><h2 style="margin-top:0">Attack Path · top {min(10, n_chains)} of {n_chains}</h2>
{ap_html or '<div class="note">no attack chains generated</div>'}</div>

<div class="panel"><h2 style="margin-top:0">All Findings</h2>
<input id="search" class="search" placeholder="Filter findings (file / detail / hint)…" autocomplete="off">
{cat_html}</div>

<div class="footer">
generated by secrethound · severity colours: CRITICAL=red HIGH=orange MEDIUM=yellow LOW=cyan INFO=blue ·
click any column header to sort · click any category header to collapse
</div>
</div><script>{_JS}</script></body></html>"""

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return out_path


def write_csv_creds(report, store, out_path):
    """Operator-friendly CSV: every CRED PAIR + PASSWORD HASH + ASSIGNED SECRET
    finding with (severity, category, file, line, user/key, secret, hint).
    Designed for easy paste into a report appendix or for awk/grep chaining."""
    import csv
    findings = report._dedup()
    keep = ("CRED PAIRS", "PASSWORD HASHES", "ASSIGNED SECRETS",
            "GPP cpassword", "ENCODED/DECODED", "PRIVATE KEYS")
    rows = [f for f in findings if f["category"] in keep]
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "category", "file", "line", "detail", "hint"])
        for f in rows:
            w.writerow([
                f["severity"], f["category"],
                report._rel(f["file"]),
                f["line"] or "",
                (f["detail"] or "").replace("\n", " "),
                (f["hint"] or "").replace("\n", " "),
            ])
    return out_path
