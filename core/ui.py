"""ui.py - terminal UI primitives for secrethound.

Pure-ANSI, ZERO dependencies (so it runs on any OSCP exam / Kali box without
pip). Inspired by winPEAS (color-coded severity legend) and feroxbuster
(config banner + live progress bar). Everything respects --no-color and
auto-sizes to the terminal width; progress goes to stderr so stdout stays
clean for piping / `script` logging / --json.
"""
import os
import sys
import shutil

# ── palette ──────────────────────────────────────────────────────────────
# 256-color where it helps, with bold for emphasis. Kali's default terminal
# renders these; --no-color strips them entirely.
C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "ital": "\033[3m",
    "under": "\033[4m",
    "red": "\033[1;31m",         # HIGH
    "bred": "\033[1;97;41m",     # CRITICAL  (white on red, like winPEAS)
    "orange": "\033[38;5;208m",
    "yellow": "\033[1;33m",      # MEDIUM
    "green": "\033[0;32m",       # INFO / ok
    "bgreen": "\033[1;32m",
    "cyan": "\033[0;36m",
    "bcyan": "\033[1;36m",
    "blue": "\033[1;34m",        # section headers
    "magenta": "\033[1;35m",
    "gray": "\033[0;90m",
    "white": "\033[1;37m",
}

# severity → (color, tag, word)
SEV = {
    "CRITICAL": ("bred", "[!!]", "CRITICAL"),
    "HIGH": ("red", "[!]", "HIGH"),
    "MEDIUM": ("yellow", "[~]", "MEDIUM"),
    "LOW": ("cyan", "[-]", "LOW"),
    "INFO": ("green", "[+]", "INFO"),
}


class UI:
    def __init__(self, use_color=True, max_width=110, ascii_only=False):
        # honour NO_COLOR convention + auto-disable when piped
        env_no = os.environ.get("NO_COLOR") is not None
        self.color = bool(use_color) and not env_no
        try:
            cols = shutil.get_terminal_size((100, 24)).columns
        except Exception:
            cols = 100
        self.cols = max(60, min(max_width, cols))
        # ASCII fallback: explicit flag, or a non-UTF8 locale
        enc = (os.environ.get("LC_ALL") or os.environ.get("LC_CTYPE")
               or os.environ.get("LANG") or "")
        self.ascii = bool(ascii_only) or ("utf" not in enc.lower() and enc != "")
        if self.ascii:
            self.box_chars = dict(tl="+", tr="+", bl="+", br="+", h="-", v="|", hh="=")
            self.bar = ("#", "-")
            self.ell = "..."
            self.arrow = "->"
            self.arrow2 = ">"
        else:
            self.box_chars = dict(tl="╔", tr="╗", bl="╚", br="╝", h="═", v="║", hh="═")
            self.bar = ("█", "░")
            self.ell = "…"
            self.arrow = "↳"
            self.arrow2 = "→"

    # ── colour ──
    def c(self, name, text):
        if not self.color or name not in C:
            return str(text)
        return f"{C[name]}{text}{C['reset']}"

    def paint(self, *names):
        """return raw escape codes for manual composition (no reset)."""
        if not self.color:
            return ""
        return "".join(C[n] for n in names if n in C)

    @property
    def rst(self):
        return C["reset"] if self.color else ""

    # ── text helpers ──
    @staticmethod
    def visible_len(s):
        out, i = 0, 0
        while i < len(s):
            if s[i] == "\033":
                j = s.find("m", i)
                if j == -1:
                    break
                i = j + 1
                continue
            out += 1
            i += 1
        return out

    def truncate_mid(self, s, maxlen):
        """keep the START and END of a long path/secret: a/b/…/y/z."""
        if len(s) <= maxlen:
            return s
        el = self.ell
        if maxlen < len(el) + 4:
            return s[:maxlen]
        keep = maxlen - len(el)
        head = (keep + 1) // 2
        tail = keep - head
        return s[:head] + el + s[-tail:]

    def truncate_end(self, s, maxlen):
        if len(s) <= maxlen:
            return s
        el = self.ell
        return s[: max(1, maxlen - len(el))] + el

    # ── rules / headers ──
    def rule(self, label="", color="blue", ch=None):
        ch = ch or self.box_chars["h"]
        if not label:
            return self.c(color, ch * self.cols)
        tag = f" {label} "
        side = self.cols - len(tag)
        left = 3
        right = max(0, side - left)
        line = ch * left + tag + ch * right
        return self.c(color, line)

    def section(self, label, count=None, color="blue"):
        """category header, e.g.  ══════════ CRED PAIRS  (3) ══════════"""
        txt = label if count is None else f"{label}  ({count})"
        tag = f" {txt} "
        bar = self.box_chars["hh"]
        side = self.cols - len(tag)
        left = 6
        right = max(0, side - left)
        return self.c(color, bar * left + tag + bar * right)

    # ── boxes ──
    def box(self, rows, title=None, color="bgreen", pad=1):
        """a bordered panel that auto-sizes; rows is a list of (already-safe)
        strings (may contain colour codes). Returns a multi-line string."""
        inner = self.cols - 2
        out = []
        g = self.box_chars
        tl, tr, bl, br, h, v = g["tl"], g["tr"], g["bl"], g["br"], g["h"], g["v"]
        if title:
            t = f" {title} "
            fill = inner - len(t)
            lead = 2
            top = tl + h * lead + t + h * max(0, fill - lead) + tr
        else:
            top = tl + h * inner + tr
        out.append(self.c(color, top))
        for r in rows:
            vis = self.visible_len(r)
            padding = " " * max(0, inner - vis - pad)
            out.append(self.c(color, v) + " " * pad + r + padding + self.c(color, v))
        out.append(self.c(color, bl + h * inner + br))
        return "\n".join(out)

    # ── banner ──
    def banner(self, version="2.0", subtitle="offline credential & secret analyzer for OSCP+ loot"):
        art = [
            r"  ___  ___ __ _ __ ___| |_  |_  ___ _  _ _ _  __| |",
            r" (_-< / -_)/ _| '_/ -_)  _| | || / _ \ || | ' \/ _` |",
            r" /__/ \___|\__|_| \___|\__| |_||_\___/\_,_|_||_\__,_|",
        ]
        lines = []
        for a in art:
            lines.append(self.c("bcyan", a))
        sep = "·" if not self.ascii else "-"
        tagline = self.c("gray", f"   v{version}  {sep}  {subtitle}")
        return "\n".join(lines) + "\n" + tagline

    # ── legend (winPEAS-style colour key) ──
    def legend(self):
        d = "-" if self.ascii else "—"
        items = [
            ("bred", "[!!] CRITICAL", f"usable cred / decoded secret / live DB row {d} act now"),
            ("red", "[!]  HIGH", "real secret value, crackable hash, private key, key file"),
            ("yellow", "[~]  MEDIUM", "probable token / hash to verify / backup / history"),
            ("cyan", "[-]  LOW", f"weak signal / high-entropy token {d} likely noise"),
            ("green", "[+]  INFO", f"interesting file located {d} read it by hand"),
        ]
        rows = [self.c("bold", "  COLOUR LEGEND")]
        for col, tag, desc in items:
            t = self.c(col, tag)
            pad = " " * max(1, 16 - self.visible_len(t))
            rows.append("    " + t + pad + self.c("gray", desc))
        return "\n".join(rows)

    # ── progress (stderr, carriage-return) ──
    def progress(self, done, total, current="", prefix="scan"):
        if not sys.stderr.isatty():
            return
        width = self.cols
        cur = self.truncate_mid(current, max(10, width - 38))
        if total:
            frac = done / total
            barw = 24
            filled = int(barw * frac)
            bar = self.bar[0] * filled + self.bar[1] * (barw - filled)
            head = f"  {prefix} [{bar}] {done}/{total} "
        else:
            spin = "|/-\\"[done % 4]
            head = f"  {prefix} {spin} {done} files "
        line = head + self.c("gray", cur)
        # pad/truncate to width, then CR
        raw = head + cur
        if len(raw) > width:
            line = head + self.c("gray", self.truncate_end(cur, width - len(head)))
        sys.stderr.write("\r\033[K" + line)
        sys.stderr.flush()

    def progress_done(self):
        if sys.stderr.isatty():
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
