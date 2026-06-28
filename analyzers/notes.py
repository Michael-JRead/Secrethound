"""notes.py - mine the operator's OWN notes for creds + resume points.

Credential extraction is delegated to analyzers.credline (the shared classifier)
so notes use the exact same real-cred-vs-noise logic as everything else - no more
grabbing 'ConvertTo-SecureString' or hydra '^PASS^' templates as passwords. On
top of that, notes adds the two note-specific signals: credential TABLE rows and
TODO/STUCK 'resume point' markers (so when you're deep in the weeds the tool
hands back your own unresolved leads).
"""
import re
from analyzers import credline, filters
from analyzers.ingest.evidence import Evidence

# credential table row:  | user | pass | host |
_TABLE = re.compile(r'^\s*\|?\s*([A-Za-z0-9._\\@-]{2,40})\s*\|\s*([^\s|]{3,40})\s*(?:\|\s*([0-9a-zA-Z._-]+)\s*)?\|?\s*$')
_TODO = re.compile(r'(?i)\b(TODO|FIXME|STUCK|revisit|come back|try later|unresolved|don\'?t forget|next step)\b')
_CREDWORD = re.compile(r'(?i)(pass|pwd|cred|login|user|secret|hash|admin|root|svc)')
_SKIP = re.compile(r'^\s*(#{1,6}\s|>\s|```|//|/\*)')


def analyze(path, report, store=None):
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.rstrip("\n")
                if not line.strip():
                    continue

                # resume markers (personal-note lines you flagged)
                if _TODO.search(line) and len(line) < 200:
                    report.add("INFO", "INTERESTING FILES", path, lineno,
                               f"resume point (you flagged this): {line.strip()[:90]}")

                if _SKIP.match(line):
                    continue

                # NOTE: generic cred lines (netexec output, user:pass, SecureString)
                # are handled by keyword.analyze (runs on every text file, incl.
                # notes) via the shared credline classifier - we don't re-emit them
                # here or we'd double-report. notes owns only TABLES + resume markers.

                # credential TABLE row (credline doesn't own these). Doc files
                # (lab-walkthrough.md, .markdown writeups) ship illustrative
                # markdown tables that aren't loot - skip the table rule there
                # but keep TODO/resume markers above.
                if filters.is_doc_file(path):
                    continue
                mt = _TABLE.match(line)
                if (mt and _CREDWORD.search(line) and credline._ok_pw(mt.group(2))
                        and mt.group(1).lower() not in ("user", "username", "host", "ip", "name")):
                    u, p, host = mt.group(1), mt.group(2), (mt.group(3) or "")
                    report.add("CRITICAL", "CRED PAIRS", path, lineno,
                               f"notes table: {u}:{p}" + (f" @{host}" if host else ""),
                               f"netexec smb {host or '<DC-IP>'} -u '{u}' -p '{p}' -k")
                    if store is not None:
                        store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                           host=host, source=path, line=lineno))
    except OSError:
        return
