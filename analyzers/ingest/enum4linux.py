"""enum4linux.py - parse enum4linux / enum4linux-ng output (text or -ng JSON).

Yields the user list (feeds spray + AS-REP), shares, and the account-lockout
threshold (so the correlator can keep spraying lockout-safe - important: a
careless spray can lock a domain account on the exam).
"""
import os
import json
import re
from analyzers.ingest.evidence import Evidence

_USER_LINE = re.compile(r'(?:user:\[(?P<u1>[^\]]+)\]|index:.*Name:\s*(?P<u2>\S+)|^\s*(?P<u3>[A-Za-z0-9._-]+)\s*$)')
_RID = re.compile(r'rid:\[0x[0-9a-f]+\]\s*user:\[([^\]]+)\]', re.I)
_SHARE = re.compile(r'^\s*(\S+)\s+(Disk|IPC|Printer)\s', re.I)
_LOCKOUT = re.compile(r'(?:lockout threshold|account lockout threshold)\D*(\d+)', re.I)


def detect(path, head):
    h = head.lower()
    if "enum4linux" in h:
        return True
    if head.lstrip().startswith("{") and ('"shares"' in h or '"users"' in h) and '"policy' in h:
        return True
    return False


def _parse_json(path, store, report):
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except (ValueError, OSError):
        return 0
    n = 0
    users = doc.get("users") or {}
    if isinstance(users, dict):
        for u in users.values():
            name = (u.get("username") or "") if isinstance(u, dict) else str(u)
            if name:
                store.add(Evidence(kind="user", user=name, source=path))
                n += 1
    pol = doc.get("policy") or doc.get("password_policy") or {}
    if isinstance(pol, dict):
        for k, v in pol.items():
            if "lockout" in k.lower() and "threshold" in k.lower():
                try:
                    store.lockout_threshold = int(re.search(r'\d+', str(v)).group())
                except (AttributeError, ValueError):
                    pass
    shares = doc.get("shares") or {}
    if isinstance(shares, dict):
        for s in shares:
            store.add(Evidence(kind="share", meta={"name": s}, source=path))
    if n:
        report.add("INFO", "RECON", path, None, f"enum4linux-ng parsed: {n} users")
    return n


def parse(path, store, report):
    head = ""
    try:
        with open(path, "r", errors="ignore") as fh:
            head = fh.read(256)
    except OSError:
        return 0
    if head.lstrip().startswith("{"):
        return _parse_json(path, store, report)
    n = 0
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                m = _RID.search(line)
                if m:
                    store.add(Evidence(kind="user", user=m.group(1), source=path))
                    n += 1
                    continue
                lo = _LOCKOUT.search(line)
                if lo:
                    try:
                        store.lockout_threshold = int(lo.group(1))
                    except ValueError:
                        pass
                sh = _SHARE.match(line)
                if sh:
                    store.add(Evidence(kind="share", meta={"name": sh.group(1)}, source=path))
    except OSError:
        return 0
    if n:
        report.add("INFO", "RECON", path, None, f"enum4linux parsed: {n} users")
    return n
