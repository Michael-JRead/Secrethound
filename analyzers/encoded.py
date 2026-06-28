"""encoded.py - detect + decode base64 values, re-scan plaintext for secrets."""
import re
import base64
import binascii
from analyzers import filters

B64 = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}')
SECRET_HINT = re.compile(r'(?i)(pass|pwd|secret|key|token|user|login|@|admin)')
# CRITICAL only when the DECODED plaintext is credential-shaped, not prose
# that merely contains a hint word. From iter-7 FP audit: 8 FPs where decoded
# values like 'this is not a secret token' or 'username=demo' got CRITICAL.
_CRED_SHAPE = re.compile(
    r'(?i)(?:'
    r'(?:pass|pwd|secret|apikey|api[_-]?key|token|auth|admin|user(?:name)?|login)\s*[:=]\s*\S{3,}'
    r'|\S+:\S{3,}@'                # user:pass@host
    r'|\S+@\S+\.\S+'              # email-shaped
    r'|^[A-Za-z0-9._@-]{2,30}:[^\s:]{3,30}$'    # bare user:pass token
    r')'
)


def _printable(b):
    try:
        s = b.decode("utf-8", errors="strict")
    except Exception:
        return None
    if all(32 <= ord(c) < 127 or c in "\t\n\r" for c in s):
        return s.strip()
    return None


def _value_after_eq(s):
    """If s looks like 'k=v' or 'k:v', return v; else None."""
    for sep in ("=", ":"):
        if sep in s:
            v = s.split(sep, 1)[1].strip()
            if v:
                return v
    return None


def analyze(path, report):
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                if not SECRET_HINT.search(line):
                    continue
                for tok in B64.findall(line):
                    if len(tok) % 4 != 0:
                        continue
                    try:
                        dec = base64.b64decode(tok, validate=True)
                    except (binascii.Error, ValueError):
                        continue
                    s = _printable(dec)
                    if not (s and 3 <= len(s) <= 80):
                        continue
                    # iter-7: drop placeholder/example decoded values
                    # ('username=demo', '{{ vault_pass }}', 'changeme', etc.)
                    if filters.is_placeholder(s) or filters.is_known_example(s):
                        continue
                    rhs = _value_after_eq(s)
                    if rhs and (filters.is_placeholder(rhs) or filters.is_known_example(rhs)):
                        continue
                    # Decoded is multi-word English prose (3+ space-separated
                    # tokens with no = / :) - not a credential shape.
                    if (" " in s and "=" not in s and ":" not in s
                            and "@" not in s and len(s.split()) >= 3):
                        continue
                    # CRITICAL only when decoded matches a credential shape
                    # (key=value, user:pass, email, user:pass@host). Otherwise
                    # MEDIUM - it's still worth surfacing as decoded content but
                    # not as an active secret.
                    sev = "CRITICAL" if _CRED_SHAPE.search(s) else "MEDIUM"
                    arr = getattr(report.ui, "arrow2", "->")
                    report.add(sev, "ENCODED/DECODED", path, lineno,
                               f"base64 '{tok[:30]}...' {arr} '{s}'")
    except Exception:
        pass
