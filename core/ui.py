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
    "dred": "\033[2;31m",        # dim red - banner dividers
    "dwhite": "\033[2;37m",      # dim white - banner tagline / status
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
            self.pip = ("#", ".")          # scoreboard stage ribbon (full, empty)
            self.g_dc = "*"                # domain-controller marker
            self.g_own = ("*", "o", ".")   # owned / partial / none
        else:
            self.box_chars = dict(tl="╔", tr="╗", bl="╚", br="╝", h="═", v="║", hh="═")
            self.bar = ("█", "░")
            self.ell = "…"
            self.arrow = "↳"
            self.arrow2 = "→"
            self.pip = ("▰", "▱")          # U+25B0/25B1 - fixed-width, widely supported
            self.g_dc = "★"                # U+2605
            self.g_own = ("◆", "◇", "·")   # U+25C6 / U+25C7 / U+00B7

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

    # decorative glyphs the tool injects into detail/hint text; transliterated
    # to ASCII when --ascii (or a non-UTF8 locale) is in effect.
    _ASCII_MAP = {"→": "->", "↳": ">", "⇒": "=>", "↔": "<->", "•": "*", "·": ".",
                  "…": "...", "★": "*", "◆": "*", "◇": "o", "▰": "#", "▱": ".",
                  "×": "x", "“": '"', "”": '"', "’": "'", "—": "-", "–": "-"}

    def ascii_safe(self, s):
        if not self.ascii or not s:
            return s
        for k, v in self._ASCII_MAP.items():
            if k in s:
                s = s.replace(k, v)
        return s

    def cell(self, text, width, color=None, align="<"):
        """fixed-width column cell: truncate/pad to the VISIBLE width FIRST, then
        colour - so colour escape codes never corrupt column alignment."""
        t = str(text)
        if self.visible_len(t) > width:
            t = self.truncate_end(t, width)
        pad = " " * max(0, width - self.visible_len(t))
        body = (t + pad) if align == "<" else (pad + t)
        return self.c(color, body) if color else body

    def ribbon(self, idx, total, color="green", at_color=None):
        """stage progress pips: filled up to and including idx, empty after."""
        full, empty = self.pip
        out = []
        for i in range(total):
            if i < idx:
                out.append(self.c(color, full))
            elif i == idx:
                out.append(self.c(at_color or color, full))
            else:
                out.append(self.c("gray", empty))
        return "".join(out)

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
    def banner(self, version="2.0",
               subtitle="Red Team Loot Intelligence"):
        """SecretHound startup banner.

        Layout (top→bottom):
            1. hound ASCII (outline white, eye @ and nose O in red)
            2. SECRET wordmark (bold white)
            3. HOUND wordmark (bold red)
            4. dim-red divider ─── tagline ─── dim-red divider
            5. status line (dim): SecretHound v<ver> — <subtitle>

        Color decisions are made HERE based on `self.color`; the
        caller in secrethound.py already gates on --no-color and
        stdout.isatty(). Suppression (--quiet/--json/non-tty stderr)
        is also handled by the caller — this method only renders.

        Under `--ascii` (self.ascii=True) the Unicode block-drawing
        wordmarks degrade to a compact figlet-standard ASCII font
        and the • bullet degrades to `.` so the banner still reads
        cleanly on terminals without Unicode box glyphs.
        """
        RED = self.paint("red")
        WHITE = self.paint("white")
        DRED = self.paint("dred")
        DWHITE = self.paint("dwhite")
        DIM = self.paint("dim")
        R = self.rst
        bul = "•" if not self.ascii else "."   # •
        rule_char = "─" if not self.ascii else "-"  # ─

        # ── hound ASCII (5 lines) — eye @ + nose O highlighted ──
        # Preserve the operator's exact whitespace + glyph layout.
        HOUND_RAW = [
            r"       / \__          ",
            r"      (    @\___      ",
            r"      /         O     ",
            r"     /   (_____/      ",
            r"    /_____/           ",
        ]
        hound = []
        for row in HOUND_RAW:
            # Inject red around @ and O, white for the rest.
            piece = row.replace("@", f"{RED}@{WHITE}") \
                       .replace("O", f"{RED}O{WHITE}")
            hound.append(f"{WHITE}{piece}{R}")

        # ── SECRET + HOUND wordmark side-by-side (6 rows) ──
        # Each row = SECRET half (bold white) + gap + HOUND half
        # (bold red). Preserved exactly from the operator's spec.
        # Total per-row width ~101 cols including gap, so this
        # requires a terminal ≥ ~103 cols with the 2-space indent.
        WORDMARK_UNICODE = [
            (r"███████╗███████╗ ██████╗██████╗ ███████╗████████╗",
             "        ",
             r"██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ "),
            (r"██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝",
             "        ",
             r"██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗"),
            (r"███████╗█████╗  ██║     ██████╔╝█████╗     ██║   ",
             "        ",
             r"███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║"),
            (r"╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   ",
             "        ",
             r"██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║"),
            (r"███████║███████╗╚██████╗██║  ██║███████╗   ██║   ",
             "        ",
             r"██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝"),
            (r"╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ",
             "        ",
             r"╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ "),
        ]
        # ASCII fallback (figlet standard, side-by-side, 5 rows)
        WORDMARK_ASCII = [
            (r"  ____                    _   ",
             "   ",
             r"  _   _                       _ "),
            (r" / ___|  ___  ___ _ __ __| |_ ",
             "   ",
             r" | | | | ___  _   _ _ __   __| |"),
            (r" \___ \ / _ \/ __| '_/ _ \  _|",
             "   ",
             r" | |_| |/ _ \| | | | '_ \ / _` |"),
            (r"  ___) |  __/ (__| | |  __/ |_",
             "   ",
             r" |  _  | (_) | |_| | | | | (_| |"),
            (r" |____/ \___|\___|_|  \___|\__|",
             "   ",
             r" |_| |_|\___/ \__,_|_| |_|\__,_|"),
        ]
        wordmark_src = (WORDMARK_ASCII if self.ascii
                        else WORDMARK_UNICODE)
        # Compose each row: SECRET (white) + gap (uncolored) + HOUND (red)
        wordmark = []
        for s_row, gap, h_row in wordmark_src:
            wordmark.append(f"  {WHITE}{s_row}{R}{gap}{RED}{h_row}{R}")
        # Compute unified wordmark width (chars, no ANSI) for
        # divider + tagline centering below.
        _line_width = 2 + len(wordmark_src[0][0]) + len(wordmark_src[0][1]) + len(wordmark_src[0][2])

        # ── divider + tagline + status ──
        # Divider width matches the combined wordmark span so the rule
        # frames the wordmark end-to-end. Tagline + status are centered
        # against that width.
        rule_width = _line_width
        rule = rule_char * (rule_width - 2)  # account for 2-space indent
        divider = f"{DRED}  {rule}{R}"
        tag_text = (f"H U N T  {bul}  C O L L E C T  "
                    f"{bul}  O R G A N I Z E")
        pad = max(0, (rule_width - len(tag_text)) // 2)
        tagline = f"{WHITE}{' ' * pad}{tag_text}{R}"
        em_dash = "—" if not self.ascii else "-"  # —
        status_text = f"SecretHound v{version}  {em_dash}  {subtitle}"
        status_pad = max(0, (rule_width - len(status_text)) // 2)
        status = f"{DWHITE}{' ' * status_pad}{status_text}{R}"

        # Compact layout — 15 lines including status, fits on an
        # 80x24 terminal vertically. Horizontal width ~103 cols; needs
        # a terminal at least ~103 columns wide (within 80-120 spec).
        return "\n".join([
            *hound,           # 5 lines
            "",
            *wordmark,        # 6 lines side-by-side SECRET HOUND
            divider,
            tagline,
            divider,
            status,
        ])

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
