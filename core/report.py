"""report.py - severity-ranked, deduplicated, colourised findings.

Rendering is delegated to core.ui (pure-ANSI, auto-sizing). The layout is
modelled on winPEAS (colour-coded severity) and feroxbuster (config + results
dashboard):  dashboard panel  ->  legend  ->  START HERE hero  ->  findings by
category  ->  NEXT STEPS.  LOW-tier (entropy) findings are collapsed by default
so real findings never drown.
"""
import os
import json
from core.ui import UI, SEV

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {"CRITICAL": "bred", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "green"}
SEV_TAG = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[-]", "INFO": "[+]"}

# category display order (max-severity categories first)
CAT_ORDER = ["ATTACK CHAINS", "CRED PAIRS", "ENCODED/DECODED", "SQLITE",
             "GPP cpassword", "ASSIGNED SECRETS", "PATTERNS", "PASSWORD HASHES",
             "PRIVATE KEYS", "RECON", "INTERESTING FILES", "HIGH ENTROPY"]
# categories scanned for the START HERE hero (highest-value first)
HERO_CATS = ["ATTACK CHAINS", "CRED PAIRS", "ENCODED/DECODED", "SQLITE",
             "GPP cpassword", "ASSIGNED SECRETS", "PASSWORD HASHES", "PRIVATE KEYS"]
_ENTROPY_PREVIEW = 12     # LOW entropy rows shown before collapsing


class Report:
    def __init__(self, use_color=True, cap_per_section=40, root=".",
                 show_low=False, group_by_dir=False, ascii_only=False):
        self.findings = []
        self.use_color = use_color
        self.cap = cap_per_section
        self.root = root
        self.show_low = show_low
        self.group_by_dir = group_by_dir
        self.ui = UI(use_color=use_color, ascii_only=ascii_only)
        self.stats = {}

    # ── data ──
    def add(self, severity, category, path, lineno, detail, hint=None):
        self.findings.append({"severity": severity, "category": category, "file": path,
                              "line": lineno, "detail": detail, "hint": hint})

    def set_stats(self, **kw):
        self.stats.update(kw)

    def _c(self, color, text):
        return self.ui.c(color, text)

    def _dedup(self):
        seen, out = set(), []
        for f in self.findings:
            key = (f["severity"], f["file"], f["detail"])
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _rel(self, path):
        if not path:
            return path
        try:
            r = os.path.relpath(path, self.root) if self.root else path
            r = path if r.startswith("..") else r
        except ValueError:
            r = path
        return r

    def _loc(self, f, width):
        loc = self._rel(f["file"]) + (f":{f['line']}" if f["line"] else "")
        return self.ui.truncate_mid(loc, width)

    def _counts(self):
        counts = {}
        for f in self._dedup():
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return counts

    # ── summary line (kept for back-compat / one-liners) ──
    def summary(self):
        counts = self._counts()
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts.get(sev):
                parts.append(self._c(SEV_COLOR[sev], f"{sev}:{counts[sev]}"))
        return "  ".join(parts) if parts else self._c("dim", "no findings")

    # ── results dashboard panel ──
    def dashboard(self):
        counts = self._counts()
        total = sum(counts.values())
        rows = []
        peak = max([counts.get(s, 0) for s in SEV_RANK] + [1])
        barmax = min(34, max(10, self.ui.cols - 30))
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            n = counts.get(sev, 0)
            if not n and sev in ("LOW",):
                continue
            barlen = int(barmax * n / peak) if peak else 0
            bar = self.ui.c(SEV_COLOR[sev], self.ui.bar[0] * barlen)
            label = self.ui.c(SEV_COLOR[sev], f"{SEV_TAG[sev]} {sev}")
            pad = " " * max(1, 16 - self.ui.visible_len(label))
            rows.append(f"{label}{pad}{self.ui.c('white', str(n)):>3}  {bar}")
        # scan stats line
        st = self.stats
        if st:
            d = "·" if not self.ui.ascii else "-"
            rows.append("")
            statline = (f"files {st.get('scanned', '?')} scanned {d} "
                        f"{st.get('skipped', 0)} skipped {d} "
                        f"{st.get('mb', 0):.1f} MB {d} {st.get('elapsed', 0):.1f}s")
            rows.append(self.ui.c("gray", statline))
        # per-machine (top-level dir) breakdown when scanning a tree
        machines = self._machine_counts()
        if len(machines) > 1:
            rows.append("")
            rows.append(self.ui.c("bold", "per directory (crit/high/med):"))
            for name, (cc, hh, mm) in machines[:12]:
                disp = self.ui.truncate_end(name, 22)
                seg = (self.ui.c("bred", str(cc)) + "/" + self.ui.c("red", str(hh)) +
                       "/" + self.ui.c("yellow", str(mm)))
                pad = " " * max(1, 24 - len(disp))
                rows.append(f"  {self.ui.c('cyan', disp)}{pad}{seg}")
        sep = "·" if not self.ui.ascii else "-"
        title = f"RESULTS  {sep}  {total} findings"
        return self.ui.box(rows, title=title, color="bgreen")

    def _machine_counts(self):
        agg = {}
        for f in self._dedup():
            rel = self._rel(f["file"])
            top = rel.split(os.sep)[0] if os.sep in rel else rel
            cc, hh, mm = agg.get(top, (0, 0, 0))
            if f["severity"] == "CRITICAL":
                cc += 1
            elif f["severity"] == "HIGH":
                hh += 1
            elif f["severity"] == "MEDIUM":
                mm += 1
            agg[top] = (cc, hh, mm)
        return sorted(agg.items(), key=lambda kv: (-kv[1][0], -kv[1][1], -kv[1][2]))

    # ── START HERE hero ──
    def hero(self):
        crits = [f for f in self._dedup() if f["severity"] == "CRITICAL"]
        pool = crits or [f for f in self._dedup()
                         if f["severity"] == "HIGH" and f["category"] in HERO_CATS]
        if not pool:
            return ""
        order = {c: i for i, c in enumerate(HERO_CATS)}
        pool.sort(key=lambda f: order.get(f["category"], 99))
        rows = []
        shown = pool[:6]
        wloc = max(20, self.ui.cols - 10)
        for f in shown:
            loc = self._loc(f, wloc)
            rows.append(self.ui.c("bred", f"{SEV_TAG[f['severity']]} ") +
                        self.ui.c("white", loc))
            rows.append("    " + self.ui.c("gray", self.ui.truncate_end(f["detail"], self.ui.cols - 8)))
            if f["hint"]:
                rows.append("    " + self.ui.c("bcyan", self.ui.arrow2 + " " + self.ui.truncate_end(f["hint"], self.ui.cols - 10)))
        if len(pool) > len(shown):
            rows.append(self.ui.c("yellow", f"{self.ui.ell} +{len(pool) - len(shown)} more critical/high - see sections below"))
        sep = "·" if not self.ui.ascii else "-"
        title = "START HERE" + (f"  {sep}  {len(crits)} critical" if crits else f"  {sep}  top leads")
        return self.ui.box(rows, title=title, color="bred")

    # ── ATTACK PATH panel (ranked next actions from the correlator) ──
    def attack_path(self, chains, top=6):
        if not chains:
            return ""
        rows = []
        best = chains[0]
        rows.append(self._c("bred", "BEST NEXT ACTION") +
                    self._c("white", f"   score {best.score}  ({best.label})"))
        for cmd in best.commands:
            rows.append("  " + self._c("bcyan", self.ui.arrow2 + " " +
                        self.ui.truncate_end(cmd, self.ui.cols - 8)))
        for ch in chains[1:top]:
            tag = self._c("yellow", "[LAB-ONLY] ") if ch.lab_only else ""
            rows.append("")
            rows.append(tag + self._c("white", f"then  score {ch.score}  ") +
                        self._c("gray", ch.summary[:self.ui.cols - 24]))
            rows.append("  " + self._c("cyan", self.ui.truncate_end(ch.commands[0], self.ui.cols - 8)))
        if len(chains) > top:
            rows.append("")
            rows.append(self._c("dim", f"  {self.ui.ell} +{len(chains) - top} more chains (see ATTACK CHAINS section / --json)"))
        rows.append("")
        rows.append(self._c("dim", "  these are SUGGESTED manual commands - you run them; the tool never does"))
        sep = "·" if not self.ui.ascii else "-"
        return self.ui.box(rows, title=f"ATTACK PATH  {sep}  {len(chains)} chains ranked", color="bred")

    # ── findings by category ──
    def render(self):
        findings = self._dedup()
        if not self.show_low:
            # keep LOW only for the HIGH ENTROPY collapse; drop other LOW noise
            pass
        findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["category"], self._rel(f["file"])))
        by_cat = {}
        for f in findings:
            by_cat.setdefault(f["category"], []).append(f)
        cats = [c for c in CAT_ORDER if c in by_cat] + [c for c in by_cat if c not in CAT_ORDER]
        out = []
        wloc = max(24, self.ui.cols - 4)
        for cat in cats:
            items = by_cat[cat]
            is_entropy = cat == "HIGH ENTROPY"
            cap = _ENTROPY_PREVIEW if (is_entropy and not self.show_low) else self.cap
            out.append("")
            out.append(self.ui.section(cat, len(items)))
            for f in items[:cap]:
                color = SEV_COLOR.get(f["severity"], "cyan")
                tag = SEV_TAG.get(f["severity"], "[?]")
                loc = self._loc(f, wloc)
                detail = self.ui.truncate_end(f["detail"], max(20, self.ui.cols - self.ui.visible_len(loc) - 10))
                out.append(self.ui.c(color, f"  {tag} ") +
                           self.ui.c("gray", loc) + "  " + self.ui.c(color, detail))
                if f["hint"]:
                    out.append("      " + self.ui.c("bcyan", self.ui.arrow + " " + self.ui.truncate_end(f["hint"], self.ui.cols - 8)))
            if len(items) > cap:
                extra = len(items) - cap
                flag = "--all" if is_entropy else "--cap N"
                out.append(self.ui.c("dim", f"      … {extra} more (raise {flag})"))
        return "\n".join(out)

    # ── JSON export ──
    def to_json(self, path, chains=None):
        out = {"stats": self.stats, "findings": self._dedup()}
        if chains:
            out["chains"] = [{
                "rule": c.rule, "label": c.label, "summary": c.summary,
                "score": c.score, "criticality": c.crit, "confidence": c.conf,
                "proximity": c.prox, "readiness": c.ready, "lab_only": c.lab_only,
                "commands": c.commands, "source": c.src, "line": c.line,
            } for c in chains]
        with open(path, "w") as fh:
            json.dump(out, fh, indent=2)
