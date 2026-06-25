"""entropy.py - Shannon entropy to catch secrets with NO keyword next to them.

This is the noisiest analyzer by nature, so it leans hard on analyzers.filters
to stay quiet. On a real HTB loot tree the old version emitted 1662 hits (LDAP
base64 GUID/SID blobs, DNs, DLL symbol names); the gate below removes those.

Findings are tier LOW by default - they are *leads*, not confirmed secrets -
and capped per line so one garbage line can't flood the report.
"""
import re
from analyzers import filters

TOKEN = re.compile(r'[A-Za-z0-9+/=_\-]{16,}')
_KV = re.compile(r'^[\w.\-]{1,60}\s*[:=]\s*(.+)$')
# secret-ish keyword anywhere on the line => let keyword/patterns own it (avoid dup)
_HAS_KEYWORD = re.compile(
    r'(?i)(pass|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|'
    r'bearer|auth|cpassword|connection|bindpw)')
_MAX_PER_LINE = 1


def analyze(path, report, threshold=4.0):
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or len(stripped) > 2000:
                    continue
                # if a real keyword is present, the keyword/pattern analyzers
                # already report it with full context - don't double-report.
                if _HAS_KEYWORD.search(stripped):
                    continue
                m = _KV.match(stripped)
                scan = m.group(1) if m else stripped
                hits = 0
                for tok in TOKEN.findall(scan):
                    if hits >= _MAX_PER_LINE:
                        break
                    if not filters.entropy_is_interesting(
                            tok, line=stripped, threshold=threshold):
                        continue
                    e = filters.shannon_entropy(tok)
                    disp = tok if len(tok) <= 60 else tok[:60] + "..."
                    report.add("LOW", "HIGH ENTROPY", path, lineno,
                               f"entropy={e:.2f}  {disp}",
                               hint="unlabeled high-entropy token - verify by hand; may be a key/token")
                    hits += 1
    except Exception:
        pass
