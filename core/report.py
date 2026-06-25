"""report.py - severity-ranked, deduplicated, colorized findings + JSON export."""
import json

C = {"red": "\033[1;31m", "yellow": "\033[1;33m", "green": "\033[0;32m",
     "cyan": "\033[0;36m", "blue": "\033[1;34m", "dim": "\033[2m", "n": "\033[0m"}
SEV_COLOR = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "INFO": "green"}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}


class Report:
    def __init__(self, use_color=True, cap_per_section=25):
        self.findings = []
        self.use_color = use_color
        self.cap = cap_per_section

    def add(self, severity, category, path, lineno, detail, hint=None):
        self.findings.append({"severity": severity, "category": category, "file": path,
                              "line": lineno, "detail": detail, "hint": hint})

    def _c(self, color, text):
        if not self.use_color:
            return text
        return f"{C[color]}{text}{C['n']}"

    def _dedup(self):
        seen, out = set(), []
        for f in self.findings:
            key = (f["severity"], f["file"], f["detail"])
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def render(self):
        findings = self._dedup()
        findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["category"], f["file"]))
        by_cat = {}
        for f in findings:
            by_cat.setdefault(f["category"], []).append(f)
        order = ["CRED PAIRS", "ENCODED/DECODED", "SQLITE", "ASSIGNED SECRETS", "PATTERNS",
                 "PASSWORD HASHES", "PRIVATE KEYS", "HIGH ENTROPY", "INTERESTING FILES"]
        cats = [c for c in order if c in by_cat] + [c for c in by_cat if c not in order]
        out = []
        for cat in cats:
            items = by_cat[cat]
            out.append(self._c("blue", f"\n══════════ {cat}  ({len(items)}) ══════════"))
            for f in items[:self.cap]:
                color = SEV_COLOR.get(f["severity"], "cyan")
                mark = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "INFO": "[+]"}.get(f["severity"], "[?]")
                loc = f["file"] + (f":{f['line']}" if f["line"] else "")
                out.append(self._c(color, f"  {mark} {loc}  {f['detail']}"))
                if f["hint"]:
                    out.append(self._c("yellow", f"      ↳ {f['hint']}"))
            if len(items) > self.cap:
                out.append(self._c("dim", f"      … {len(items) - self.cap} more (raise --cap)"))
        return "\n".join(out)

    def summary(self):
        findings = self._dedup()
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
            if sev in counts:
                parts.append(self._c(SEV_COLOR[sev], f"{sev}:{counts[sev]}"))
        return "  ".join(parts) if parts else self._c("dim", "no findings")

    def to_json(self, path):
        with open(path, "w") as fh:
            json.dump(self._dedup(), fh, indent=2)
