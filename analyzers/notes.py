"""notes.py - mine the operator's OWN notes for creds + resume points.

Catches what the generic detectors miss in free-form notes: 'GETS PASSWORD: x'
lines, credential tables (| user | pass | host |), 'creds: u/p', and TODO/STUCK
markers (so a tool can hand back unresolved leads when you're deep in the weeds).
Feeds Evidence so notes-creds join the spray/auth chains. Hashes in notes are
already handled by patterns.analyze in the main loop.
"""
import re
from analyzers import filters
from analyzers.ingest.evidence import Evidence

_GETS = re.compile(r'(?i)\b(?:gets?\s+password|password\s+is|pass(?:word)?\s*[:=]|creds?\s*[:=])\s*([^\s,;]{3,60})')
_USERPASS = re.compile(r'(?i)\b([A-Za-z0-9._\\@-]{2,40})\s*[:/]\s*([^\s,;|]{3,40})')
_TABLE = re.compile(r'^\s*\|?\s*([A-Za-z0-9._\\@-]{2,40})\s*\|\s*([^\s|]{3,40})\s*(?:\|\s*([0-9a-zA-Z._-]+)\s*)?\|?\s*$')
_USERHINT = re.compile(r'(?i)\b(user(?:name)?|login|account)\b\s*[:=]\s*([A-Za-z0-9._\\@-]{2,40})')
_TODO = re.compile(r'(?i)\b(TODO|FIXME|STUCK|revisit|come back|try later|unresolved|don\'?t forget)\b')
_SKIP = re.compile(r'^\s*(#{1,6}\s|>\s|```|//|/\*)')
_CREDWORD = re.compile(r'(?i)(pass|pwd|cred|login|user|secret|hash|admin|root|svc)')


def _good(v):
    v = v.strip().strip("'\"`")
    return v and 3 <= len(v) <= 60 and not filters.is_placeholder(v) \
        and not filters.is_known_example(v) and not filters.is_code_not_literal(v, v)


def analyze(path, report, store=None):
    last_user = ""
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.rstrip("\n")
                if not line.strip():
                    continue

                # resume markers (only when they look like a personal note line)
                if _TODO.search(line) and len(line) < 200:
                    report.add("INFO", "INTERESTING FILES", path, lineno,
                               f"resume point (you flagged this): {line.strip()[:90]}")

                if _SKIP.match(line):
                    continue

                mu = _USERHINT.search(line)
                if mu and _good(mu.group(2)):
                    last_user = mu.group(2).strip()

                # "GETS PASSWORD: x" / "password is x" / "creds: x"
                mg = _GETS.search(line)
                if mg and _good(mg.group(1)) and _CREDWORD.search(line):
                    pw = mg.group(1).strip().strip("'\"`")
                    report.add("CRITICAL", "CRED PAIRS", path, lineno,
                               f"notes: PASS={pw}" + (f" (USER~{last_user})" if last_user else ""),
                               f"netexec smb <DC-IP> -u '{last_user or '<user>'}' -p '{pw}' -k")
                    if store is not None:
                        store.add(Evidence(kind="plaintext", user=last_user, plaintext=pw,
                                           source=path, line=lineno))
                    continue

                # credential table row:  | user | pass | host |
                mt = _TABLE.match(line)
                if mt and _CREDWORD.search(line) and _good(mt.group(2)) \
                        and mt.group(1).lower() not in ("user", "username", "host", "ip"):
                    u, p, host = mt.group(1), mt.group(2), (mt.group(3) or "")
                    report.add("CRITICAL", "CRED PAIRS", path, lineno,
                               f"notes table: {u}:{p}" + (f" @{host}" if host else ""),
                               f"netexec smb {host or '<DC-IP>'} -u '{u}' -p '{p}' -k")
                    if store is not None:
                        store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                           host=host, source=path, line=lineno))
    except OSError:
        return
