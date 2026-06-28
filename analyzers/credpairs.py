"""credpairs.py - correlate username + password found in the same file.

A user + a password in the same file is the single highest-value finding for
OSCP (it's a ready-to-spray credential), so this is CRITICAL. Values are gated
through analyzers.filters to drop placeholder/dummy/code pairs.
"""
import re
from analyzers import filters

USER_KEY = re.compile(
    r'\b(user(?:name)?|login|account|uid|db_user|smtp_user|ftp_user|sa_user|'
    r'ldap_account_service_login|admin_user|wapt_user|sAMAccountName)\b\s*[:=]\s*(.+)',
    re.IGNORECASE)
PASS_KEY = re.compile(
    r'\b(pass(?:word|wd)?|pwd|secret|db_pass|bindpw|sa_password|'
    r'ldap_account_service_password|admin_pass)\b\s*[:=]\s*(.+)', re.IGNORECASE)
SKIP_LINE = re.compile(r'^\s*(#|//|\*|;|--\s)')
_B64ISH = re.compile(r'^[A-Za-z0-9+/]{12,}={0,2}$')


def _clean(value):
    v = re.split(r'\s+[#;]\s', value)[0].strip()
    # if the value starts with a quote, take exactly up to the matching close quote
    # (so `'pass';` -> `pass`, not `pass';`)
    if v[:1] in ("'", '"'):
        q = v[0]
        end = v.find(q, 1)
        if end > 0:
            return v[1:end]
    return v.strip("'\"").rstrip(";,)} \t")


def _good(raw, line):
    v = _clean(raw)
    if not v or " " in v or not (2 < len(v) < 80):
        return None
    if filters.is_placeholder(raw) or filters.is_known_example(raw):
        return None
    if filters.is_code_not_literal(raw, line):
        return None
    return v


_FTP_USER = re.compile(r'^\s*USER\s+(\S{2,40})\s*$')
_FTP_PASS = re.compile(r'^\s*PASS\s+(\S{3,80})\s*$')


def analyze(path, report):
    users, passes = [], []
    ftp_user = ftp_pass = None
    ftp_ln = None
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                # FTP/POP/IMAP cleartext protocol commands (tshark / pcap export,
                # telnet logs). Captured separately from the key=value pairing.
                fu = _FTP_USER.match(line)
                if fu and not ftp_user:
                    ftp_user, ftp_ln = fu.group(1), lineno
                fp = _FTP_PASS.match(line)
                if fp and not ftp_pass:
                    ftp_pass = fp.group(1)
                if SKIP_LINE.match(line):
                    continue
                mu = USER_KEY.search(line)
                if mu:
                    v = _good(mu.group(2), line)
                    if v:
                        users.append((lineno, line.strip(), v))
                mp = PASS_KEY.search(line)
                if mp:
                    v = _good(mp.group(2), line)
                    if v:
                        passes.append((lineno, line.strip(), v))
    except Exception:
        return
    if ftp_user and ftp_pass and not filters.is_placeholder(ftp_pass):
        report.add("CRITICAL", "CRED PAIRS", path, ftp_ln,
                   f"cleartext protocol login: {ftp_user}:{ftp_pass}",
                   hint=f"captured FTP/POP/IMAP creds - reuse: ssh {ftp_user}@<ip>  /  "
                        f"netexec smb <ip> -u '{ftp_user}' -p '{ftp_pass}'")
    if users and passes:
        u_val = users[0][2]
        p_val = passes[0][2]
        detail = f"USER={u_val}  PASS={p_val}"
        if _B64ISH.fullmatch(p_val) and filters.decodes_to_text(p_val):
            dec = filters.decodes_to_text(p_val)
            hint = (f"PASS looks base64 -> '{dec}'.  validate: "
                    f"netexec smb <dc> -u '{u_val}' -p '{dec}' -k")
        else:
            hint = f"netexec smb <dc> -u '{u_val}' -p '{p_val}' -k   (spray: add users.txt --continue-on-success)"
        report.add("CRITICAL", "CRED PAIRS", path, None, detail, hint)
        for ln, txt, val in users[1:3]:
            report.add("HIGH", "CRED PAIRS", path, ln, f"extra USER: {val}")
        for ln, txt, val in passes[1:3]:
            report.add("HIGH", "CRED PAIRS", path, ln, f"extra PASS: {val}")
