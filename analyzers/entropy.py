"""entropy.py - Shannon entropy to catch secrets with NO keyword next to them."""
import math
import re

TOKEN = re.compile(r'[A-Za-z0-9+/=_\-]{16,}')
HEX = re.compile(r'^[0-9a-fA-F]+$')
WORD = re.compile(r'^[A-Za-z]+$')
COMMON_NOISE = re.compile(
    r'(application|configuration|authorization|implementation|initialization|'
    r'representation|cryptography|certificate|requirements|dependencies|'
    r'AAAAAAAA|00000000|11111111|xxxxxxxx)', re.IGNORECASE)


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_noise(tok):
    if HEX.match(tok) and len(tok) in (16, 32, 40, 56, 64, 128):
        return False
    if WORD.match(tok):
        return True
    if re.fullmatch(r'[a-z][a-z0-9]*(_[a-z0-9]+)+', tok):
        return True
    if re.fullmatch(r'[a-z_]+', tok):
        return True
    if tok.count("/") > 2 or tok.startswith("http"):
        return True
    if COMMON_NOISE.search(tok):
        return True
    if HEX.match(tok) and len(tok) > 128:
        return True
    has_digit = any(c.isdigit() for c in tok)
    has_upper = any(c.isupper() for c in tok)
    has_lower = any(c.islower() for c in tok)
    has_b64sym = any(c in "+/=" for c in tok)
    # real secrets: mixed-case alnum, or base64 symbols, or long hex
    if not ((has_upper and has_lower and has_digit) or has_b64sym or (HEX.match(tok) and len(tok) >= 32)):
        return True
    return False


def analyze(path, report, threshold=4.0):
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                # only scan the VALUE side of key=value (kills kwarg noise)
                _sc = line.strip(); _m = re.match(r'^[\w.\-]{1,60}\s*[:=]\s*(.+)$', _sc)
                for tok in TOKEN.findall(_m.group(1) if _m else _sc):
                    if _is_noise(tok):
                        continue
                    if not any(ch.isdigit() for ch in tok):
                        continue
                    e = shannon_entropy(tok)
                    if e >= threshold:
                        disp = tok if len(tok) <= 60 else tok[:60] + "..."
                        report.add("MEDIUM", "HIGH ENTROPY", path, lineno, f"entropy={e:.2f}  {disp}")
    except Exception:
        pass
