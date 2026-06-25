"""encoded.py - detect + decode base64 values, re-scan plaintext for secrets."""
import re
import base64
import binascii

B64 = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}')
SECRET_HINT = re.compile(r'(?i)(pass|pwd|secret|key|token|user|login|@|admin)')


def _printable(b):
    try:
        s = b.decode("utf-8", errors="strict")
    except Exception:
        return None
    if all(32 <= ord(c) < 127 or c in "\t\n\r" for c in s):
        return s.strip()
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
                    if s and 3 <= len(s) <= 80:
                        sev = "CRITICAL" if SECRET_HINT.search(s) else "MEDIUM"
                        report.add(sev, "ENCODED/DECODED", path, lineno, f"base64 '{tok[:30]}...' → '{s}'")
    except Exception:
        pass
