"""inspect.py - single-file deep-dive (the lootx feature)."""
import re

INTEREST = re.compile(
    r'(?i)(pass(?:word|wd)?|pwd|secret|api[_-]?key|token|bind|login|user(?:name)?|'
    r'host|ldap_|db_|cred|auth|\$[0-9]|\$2[aby]\$|BEGIN .*PRIVATE KEY|AKIA|eyJ)')
SKIP = re.compile(r'^\s*(#|//|\*|;|--\s)')
HOT = re.compile(r'(?i)(pass(?:word|wd)?|secret|pwd|\$[0-9]|AKIA|BEGIN .*PRIVATE KEY|eyJ)')
C = {"red": "\033[1;31m", "yellow": "\033[1;33m", "green": "\033[0;32m",
     "cyan": "\033[0;36m", "dim": "\033[2m", "n": "\033[0m"}


def deep_dive(path, use_color=True, limit=80):
    def c(color, t):
        return f"{C[color]}{t}{C['n']}" if use_color else t
    print(c("green", f"\n╔══ DEEP DIVE → {path} ══╗"))
    shown = 0
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if SKIP.match(line) or not INTEREST.search(line):
                    continue
                disp = line.strip()
                if len(disp) > 160:
                    disp = disp[:160] + "..."
                color = "red" if HOT.search(line) else "yellow"
                print(c(color, f"  L{lineno:<4} ") + c("dim", "│ ") + c(color, disp))
                shown += 1
                if shown >= limit:
                    print(c("dim", f"  … stopped at {limit} lines (file has more)"))
                    break
    except Exception as e:
        print(c("red", f"  [x] could not read: {e}"))
        return
    if shown == 0:
        print(c("dim", "  no secret-bearing lines matched — read the raw file, secret may be unlabeled"))
    print(c("green", "╚" + "═" * 40 + "╝"))
