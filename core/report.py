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

    def _counts(self, exclude_cats=()):
        counts = {}
        for f in self._dedup():
            if f["category"] in exclude_cats:
                continue
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
        counts = self._counts(exclude_cats=("ATTACK CHAINS",))
        n_chains = sum(1 for f in self._dedup() if f["category"] == "ATTACK CHAINS")
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
        sep = "·" if not self.ui.ascii else "-"
        title = f"RESULTS  {sep}  {total} findings"
        if n_chains:
            title += f"  {sep}  {n_chains} attack chains"
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

    def _top(self, path):
        rel = self._rel(path)
        return rel.split(os.sep)[0] if (rel and os.sep in rel) else (rel or "")

    # ── per-machine ENGAGEMENT SCOREBOARD (one honest row per loot dir) ──
    # furthest *verifiable* progress per box - we never claim privesc/DA we
    # can't prove from the loot we hold.
    STAGES = ["recon", "access", "creds", "admin"]
    # markers of *achieved* admin/DA - only matched against EVIDENCE findings,
    # never against ATTACK CHAINS (those carry suggested 'if Pwn3d!' commands).
    _ADMIN_MARK = ("pwn3d", "ntds dump", "dcsync", "sam+system", "domain admin")

    def _machine_state(self, chains, store):
        st = {}

        def m(name):
            return st.setdefault(name, {"creds": 0, "hashes": 0, "stage": 0,
                                        "svc": set(), "dc": False, "best": None})

        for f in self._dedup():
            if f["category"] == "ATTACK CHAINS":
                continue          # suggestions, not evidence of progress
            name = self._top(f["file"])
            if not name:
                continue
            d = m(name)
            cat, det = f["category"], (f["detail"] or "")
            hint = (f["hint"] or "")
            blob = (det + " " + hint).lower()
            if cat == "CRED PAIRS" and "failed" not in blob:
                d["creds"] += 1
                d["stage"] = max(d["stage"], 2)
            elif cat == "PASSWORD HASHES":
                d["hashes"] += 1
                d["stage"] = max(d["stage"], 2)
            elif cat in ("PRIVATE KEYS", "GPP cpassword"):
                d["stage"] = max(d["stage"], 1)
            elif cat == "INTERESTING FILES" and any(
                    x in (f["file"] or "").lower() for x in (".pfx", ".p12", ".kirbi", ".ccache")):
                d["stage"] = max(d["stage"], 1)
            if "administrator" in blob and cat in ("PASSWORD HASHES", "CRED PAIRS"):
                d["stage"] = max(d["stage"], 3)
            if any(k in blob for k in self._ADMIN_MARK):
                d["stage"] = max(d["stage"], 3)

        # services + DC from ingested evidence (nmap / netexec text logs)
        if store is not None:
            for ev in store.by_kind("service"):
                name = self._top(ev.source)
                if name and ev.service:
                    m(name)["svc"].add(ev.service)
            for ev in store.by_kind("host"):
                if ev.fact == "dc":
                    name = self._top(ev.source)
                    if name:
                        m(name)["dc"] = True

        # best chain (highest score) sourced from each machine's dir
        for c in (chains or []):
            name = self._top(getattr(c, "src", "") or "")
            if name in st and (st[name]["best"] is None or c.score > st[name]["best"].score):
                st[name]["best"] = c
        return st

    def scoreboard(self, chains, store):
        st = self._machine_state(chains, store)
        if len(st) < 2:
            return ""
        ui = self.ui
        dot = "·" if not ui.ascii else "."
        order = sorted(st.items(),
                       key=lambda kv: (-kv[1]["stage"],
                                       -(kv[1]["best"].score if kv[1]["best"] else 0),
                                       -kv[1]["creds"] - kv[1]["hashes"]))
        rows = [ui.c("dim", "  " + ui.cell("HOST", 16) + ui.cell("STAGE", 8) +
                     ui.cell("", 6) + ui.cell("CRD", 4, align=">") +
                     ui.cell("HSH", 5, align=">") + "  " + "BEST NEXT MOVE")]
        n_admin = 0
        for name, d in order:
            si = d["stage"]
            if si >= 3:
                n_admin += 1
            stage_word = self.STAGES[si]
            scol = "bred" if si >= 3 else "bgreen" if si == 2 else "yellow" if si == 1 else "gray"
            ribbon = ui.ribbon(si, len(self.STAGES),
                               color="green", at_color="bred" if si >= 3 else "bgreen")
            disp = (ui.g_dc + name) if d["dc"] else name
            nxt = ""
            if d["best"]:
                nxt = d["best"].summary
            elif d["svc"]:
                nxt = "services: " + " ".join(sorted(d["svc"])[:5])
            else:
                nxt = "read files by hand - no creds yet"
            # prefix = 2 + HOST16 + STAGE8 + ribbon4 + 2 + CRD4 + HSH5 + 2 = 43;
            # box steals 2 borders + 1 lead pad -> usable inner is cols-3
            nxt_w = max(20, (ui.cols - 3) - 43)
            rows.append(
                "  " + ui.cell(disp, 16, "bcyan") + ui.cell(stage_word, 8, scol) +
                ribbon + "  " +
                ui.cell(d["creds"] or dot, 4, "white" if d["creds"] else "dim", ">") +
                ui.cell(d["hashes"] or dot, 5, "white" if d["hashes"] else "dim", ">") +
                "  " + ui.c("gray", ui.truncate_end(nxt, nxt_w)))
        sep = "·" if not ui.ascii else "-"
        owned = f"  {sep}  {n_admin} to admin" if n_admin else ""
        title = f"ENGAGEMENT SCOREBOARD  {sep}  {len(st)} hosts{owned}"
        return ui.box(rows, title=title, color="bcyan")

    # ── START HERE hero ──
    # raw high-value LOOT (cred values, decoded secrets, GPP) - complementary to
    # the ATTACK PATH panel, which renders the ranked MOVES, so we exclude
    # ATTACK CHAINS here to avoid showing the same thing twice.
    def hero(self):
        crits = [f for f in self._dedup()
                 if f["severity"] == "CRITICAL" and f["category"] != "ATTACK CHAINS"]
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
            rows.append("    " + self.ui.c("gray", self.ui.truncate_end(self.ui.ascii_safe(f["detail"]), self.ui.cols - 8)))
            if f["hint"]:
                rows.append("    " + self.ui.c("bcyan", self.ui.arrow2 + " " + self.ui.truncate_end(self.ui.ascii_safe(f["hint"]), self.ui.cols - 10)))
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

    # ── compact roll-up band for big hash sections (trivy/grype style) ──
    _HASH_PLAN = {
        "NTLM (NT)": ("1000", "pass-the-hash live, or crack -m 1000"),
        "AS-REP roast": ("18200", "crack -m 18200 (no creds needed)"),
        "Kerberoast TGS": ("13100", "crack -m 13100 rockyou+best64"),
        "sha512crypt": ("1800", "crack -m 1800"),
        "md5crypt": ("500", "crack -m 500"),
        "bcrypt": ("3200", "crack -m 3200"),
        "DCC2": ("2100", "crack -m 2100 (slow)"),
        "blank NT": ("", "NO password - try empty / null auth"),
    }

    def _hash_type(self, det):
        if det.startswith("NTLM (NT)"):
            return "NTLM (NT)"
        if "NT is blank" in det or "blank NT" in det:
            return "blank NT"
        if "AS-REP" in det:
            return "AS-REP roast"
        if "TGS" in det or "Kerberoast" in det:
            return "Kerberoast TGS"
        for k in ("sha512crypt", "md5crypt", "sha256crypt", "bcrypt", "yescrypt", "DCC2"):
            if det.startswith(k) or k.lower() in det.lower():
                return k
        return det.split(":")[0][:18]

    def _hash_rollup(self, items):
        """compact crack-plan band; returns None unless the section is long or
        has real concentration (so small all-distinct sections stay clean)."""
        agg = {}
        for f in items:
            t = self._hash_type(f["detail"] or "")
            src = self._top(f["file"]) or self._rel(f["file"])
            agg[(src, t)] = agg.get((src, t), 0) + 1
        if len(items) < 8 and len(agg) >= len(items):
            return None        # all distinct, short -> the plain list is clearer
        rows = [self.ui.c("dim", "  " + self.ui.cell("", 5) + self.ui.cell("TYPE", 16) +
                          self.ui.cell("SOURCE", 18) + "CRACK / USE")]
        mult = "×" if not self.ui.ascii else "x"
        for (src, t), n in sorted(agg.items(), key=lambda kv: -kv[1]):
            plan = self._HASH_PLAN.get(t, ("", "hashid first, then hashcat -m <mode>"))[1]
            cnt = self.ui.cell(f"{n}{mult}", 4, "yellow" if n > 5 else "white", ">")
            rows.append("  " + cnt + " " + self.ui.cell(t, 16, "white") +
                        self.ui.cell(self.ui.truncate_end(src, 17), 18, "bcyan") +
                        self.ui.c("gray", self.ui.truncate_end(plan, max(16, self.ui.cols - 47))))
        return self.ui.box(rows, color="red")

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
            # at-a-glance crack plan when a hash section gets long / concentrated
            rolled = False
            if cat == "PASSWORD HASHES":
                band = self._hash_rollup(items)
                if band:
                    out.append(band)
                    rolled = True
                    if not self.show_low:
                        cap = min(cap, 6)  # rollup carries totals; show a few samples
            for f in items[:cap]:
                color = SEV_COLOR.get(f["severity"], "cyan")
                tag = SEV_TAG.get(f["severity"], "[?]")
                loc = self._loc(f, wloc)
                detail = self.ui.truncate_end(self.ui.ascii_safe(f["detail"]),
                                              max(20, self.ui.cols - self.ui.visible_len(loc) - 10))
                out.append(self.ui.c(color, f"  {tag} ") +
                           self.ui.c("gray", loc) + "  " + self.ui.c(color, detail))
                if f["hint"]:
                    out.append("      " + self.ui.c("bcyan", self.ui.arrow + " " +
                               self.ui.truncate_end(self.ui.ascii_safe(f["hint"]), self.ui.cols - 8)))
            if len(items) > cap:
                extra = len(items) - cap
                if rolled:
                    out.append(self.ui.c("dim", f"      {self.ui.ell} +{extra} more (all counted above) "
                                         f"- full user:hash list via --all or --json"))
                else:
                    flag = "--all" if is_entropy else "--cap N"
                    out.append(self.ui.c("dim", f"      {self.ui.ell} {extra} more (raise {flag})"))
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
