"""enum4linux.py - parse enum4linux / enum4linux-ng output (text or -ng JSON).

Yields the user list (feeds spray + AS-REP), shares, and the account-lockout
threshold (so the correlator can keep spraying lockout-safe - important: a
careless spray can lock a domain account on the exam).
"""
import os
import json
import re
from analyzers import filters
from analyzers.ingest.evidence import Evidence

_USER_LINE = re.compile(r'(?:user:\[(?P<u1>[^\]]+)\]|index:.*Name:\s*(?P<u2>\S+)|^\s*(?P<u3>[A-Za-z0-9._-]+)\s*$)')
_RID = re.compile(r'rid:\[0x[0-9a-f]+\]\s*user:\[([^\]]+)\]', re.I)
# iter-126: enum4linux's 'Domain Sid: S-1-5-21-...' line seeds
# Store.domain_sid() so downstream ticketer commands emit real SIDs.
_DOM_SID = re.compile(
    r'(?im)^\s*(?:\[\+\]\s+)?Domain\s+SID(?:\s+is)?\s*:\s*(S-1-5-21-\d+-\d+-\d+)\s*$')
# iter-126: enum4linux / enum4linux-ng RID cycling emits SID lines like:
#   S-1-5-21-100-200-300-500 LAB\Administrator (Local User)
#   S-1-5-21-100-200-300-1104 LAB\svc_backup (Local User)
# Only match 'Local User' - Local Group / Domain Group would seed group
# names which are less useful for spray/roast candidates. Capture the
# full SID so it also seeds Store.domain_sid() via principal_sid.
_RID_SID = re.compile(
    r'^(S-1-5-21-\d+-\d+-\d+-\d+)\s+([^\\\s]+)\\([^\s()]+)\s+\(Local User\)\s*$',
    re.MULTILINE)
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
            if not isinstance(u, dict):
                # bare string value (older enum4linux-ng)
                if u:
                    store.add(Evidence(kind="user", user=str(u), source=path))
                    n += 1
                continue
            name = (u.get("username") or u.get("name") or "")
            if not name:
                continue
            store.add(Evidence(kind="user", user=name, source=path))
            n += 1
            # iter-24: scrape description / fullname / comment / homedir for
            # embedded cleartext via the shared 'password is X' extractor.
            # AD users RID-walk dumps put hints here on routine THM rooms.
            desc = " ".join(str(u.get(k) or "") for k in
                            ("description", "fullname", "full_name",
                             "comment", "remark", "homedir", "home_directory"))
            tok = filters.extract_pw_from_desc(desc)
            if tok and not filters.is_placeholder(tok) \
                    and not filters.is_code_not_literal(tok, desc):
                # iter-140: shell-safe escape for the hint's -p value.
                _tok_sh = tok.replace("'", "'\\''")
                report.add("HIGH", "CRED PAIRS", path, None,
                           f"enum4linux-ng desc cred for {name}: {desc[:80]}",
                           f"try: netexec smb <DC-IP> -u '{name}' -p '{_tok_sh}'")
                store.add(Evidence(kind="plaintext", user=name, plaintext=tok,
                                   source=path))
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
            text = fh.read()
    except OSError:
        return 0
    # iter-126: RID_SID matches multi-line so it needs the full file
    # buffer once, not per-line.
    for m in _RID_SID.finditer(text):
        sid, dom, user = m.group(1), m.group(2), m.group(3)
        store.add(Evidence(kind="user", user=user, domain=dom, source=path,
                           meta={"principal_sid": sid}))
        n += 1
    for m in _DOM_SID.finditer(text):
        store.add(Evidence(kind="ldap_attr", source=path,
                           meta={"dc_sid": m.group(1)}))
        n += 1
    for line in text.splitlines():
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
    if n:
        report.add("INFO", "RECON", path, None, f"enum4linux parsed: {n} users")
    return n
