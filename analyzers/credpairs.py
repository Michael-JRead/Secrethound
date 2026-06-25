"""credpairs.py - correlate username + password found in the same file."""
import re

USER_KEY = re.compile(
    r'\b(user(?:name)?|login|account|uid|db_user|smtp_user|ftp_user|'
    r'ldap_account_service_login|admin_user|wapt_user)\b\s*[:=]\s*(.+)', re.IGNORECASE)
PASS_KEY = re.compile(
    r'\b(pass(?:word|wd)?|pwd|secret|db_pass|bindpw|'
    r'ldap_account_service_password|admin_pass)\b\s*[:=]\s*(.+)', re.IGNORECASE)
NOISE_VALUE = re.compile(
    r'^["\']?\s*(|none|null|false|true|changeme|example|<[^>]+>|\{\{.*|\$\{.*|'
    r'%[sd].*|getpass\b.*|os\.environ.*|conf\[.*|self\..*|input\(.*)\s*["\']?\s*$', re.IGNORECASE)
SKIP_LINE = re.compile(r'^\s*(#|//|\*|;|--\s)')


def _code_like(v):
    return bool(re.search(r'[()\[\]{}]|\.encode|\.lower|\.get|=|,$|:$|\bNone\b|\bself\b|callback', v))


def _clean(value):
    return re.split(r'\s+[#;]\s', value)[0].strip().strip("'\"")


def analyze(path, report):
    users, passes = [], []
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                if SKIP_LINE.match(line):
                    continue
                mu = USER_KEY.search(line)
                if mu:
                    v = _clean(mu.group(2))
                    if v and not NOISE_VALUE.match(mu.group(2).strip()) and not _code_like(v) and ' ' not in v and 2 < len(v) < 60:
                        users.append((lineno, line.strip(), v))
                mp = PASS_KEY.search(line)
                if mp:
                    v = _clean(mp.group(2))
                    if v and not NOISE_VALUE.match(mp.group(2).strip()) and not _code_like(v) and ' ' not in v and 2 < len(v) < 60:
                        passes.append((lineno, line.strip(), v))
    except Exception:
        return
    if users and passes:
        u_val = users[0][2]
        p_val = passes[0][2]
        detail = f"USER={u_val}  PASS={p_val}"
        if re.fullmatch(r'[A-Za-z0-9+/]{12,}={0,2}', p_val):
            hint = f"echo '{p_val}' | base64 -d   then: netexec smb <dc> -u '{u_val}' -p '<decoded>' -k"
        else:
            hint = f"netexec smb <dc> -u '{u_val}' -p '{p_val}' -k"
        report.add("CRITICAL", "CRED PAIRS", path, None, detail, hint)
        for ln, txt, val in users[1:3]:
            report.add("HIGH", "CRED PAIRS", path, ln, f"extra USER: {val}")
        for ln, txt, val in passes[1:3]:
            report.add("HIGH", "CRED PAIRS", path, ln, f"extra PASS: {val}")
