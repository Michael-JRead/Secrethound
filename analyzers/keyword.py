"""keyword.py - secret_name = real_value, plus high-value AD content shapes.

Two passes:
  1. generic `keyword = value` (filtered hard via analyzers.filters)
  2. AD/Windows content patterns that hide plaintext creds without a classic
     `password =` (ConvertTo-SecureString, AutoAdminLogon, runas /savecred,
     net user, SQL IDENTIFIED BY, DOMAIN\\user:pass)
"""
import os
import re
from analyzers import filters

KEY = re.compile(
    r'\b(pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|'
    r'token|auth[_-]?token|bearer|bindpw|db_pass(?:word)?|smtp_pass|ftp_pass|sa_password|'
    r'ldap_account_service_password|private[_-]?key[_-]?password|client[_-]?secret|'
    r'master[_-]?key|encryption[_-]?key|secret[_-]?key[_-]?base|jwt[_-]?secret|'
    r'connection[_-]?string|conn[_-]?str|_authtoken|requirepass|masterauth)\b'
    r'\s*[:=]\s*(.+)', re.IGNORECASE)
SKIP_LINE = re.compile(r'^\s*(#|//|\*|/\*|--\s|;)')

# code filetypes: require the value to be QUOTED (detect-secrets lesson) so we
# don't flag `password = getSecret()` or `password = None` in source.
_CODE_EXT = {".js", ".ts", ".py", ".rb", ".php", ".pl", ".ps1", ".java", ".go",
             ".c", ".cpp", ".cs", ".sh", ".tf", ".groovy"}

# ── AD / Windows plaintext-cred content shapes ─────────────────────────────
AD_PATTERNS = [
    ("PowerShell SecureString", "CRITICAL", re.compile(
        r'(?i)ConvertTo-SecureString\s+(?:-String\s+)?["\']([^"\']{3,})["\']\s*-AsPlainText')),
    ("PowerShell SecureString", "CRITICAL", re.compile(
        r'(?i)ConvertTo-SecureString\s+["\']([^"\']{3,})["\']')),
    ("autologon password", "HIGH", re.compile(
        r'(?i)(?:DefaultPassword|AutoAdminLogon\s+password)\s*[":=]+\s*["\']?([^"\'\r\n]{2,})')),
    ("runas /savecred", "HIGH", re.compile(
        r'(?i)runas\s+/savecred\s+/user:(\S+)')),
    ("net user add", "HIGH", re.compile(
        r'(?i)net\s+user\s+(\S+)\s+(\S+)\s+/add')),
    ("SQL IDENTIFIED BY", "HIGH", re.compile(
        r'(?i)IDENTIFIED\s+BY\s+["\']([^"\']{2,})["\']')),
    ("mysql -p inline", "HIGH", re.compile(
        r'(?i)mysql\s+.*-p(\S{2,})')),
    ("sshpass", "HIGH", re.compile(
        r'(?i)sshpass\s+-p\s*["\']?([^"\'\s]{2,})')),
    ("DOMAIN\\user:pass", "HIGH", re.compile(
        r'\b([A-Za-z0-9._-]{2,}\\[A-Za-z0-9._-]{2,}):([^\s:"\']{3,})')),
]


def _value_ok(value, line):
    """central FP gate for a keyword value."""
    cv = value.strip().strip("'\"")
    if len(cv) < 3 or len(cv) > 200:
        return False
    if filters.is_placeholder(value) or filters.is_known_example(value):
        return False
    if filters.is_code_not_literal(value, line):
        return False
    return True


def analyze(path, report):
    ext = os.path.splitext(path)[1].lower()
    require_quote = ext in _CODE_EXT
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if SKIP_LINE.match(line):
                    continue

                # ---- pass 2: AD/Windows content shapes ----
                for name, sev, rx in AD_PATTERNS:
                    am = rx.search(line)
                    if not am:
                        continue
                    val = am.group(am.lastindex) if am.lastindex else am.group(0)
                    if filters.is_placeholder(val) or filters.is_code_not_literal(val, line):
                        continue
                    snip = line.strip()
                    if len(snip) > 140:
                        snip = snip[:140] + "..."
                    report.add(sev, "ASSIGNED SECRETS", path, lineno,
                               f"{name}: {snip}",
                               hint="plaintext credential in script/config - reuse directly")
                    break

                # ---- pass 1: generic keyword = value ----
                m = KEY.search(line)
                if not m:
                    continue
                value = re.split(r'\s+[#;]\s', m.group(2).strip())[0].strip()
                if not value:
                    continue
                if require_quote and not (value[:1] in "'\"" or '"' in value or "'" in value):
                    continue
                if not _value_ok(value, line):
                    continue
                snippet = line.strip()
                if len(snippet) > 140:
                    snippet = snippet[:140] + "..."
                report.add("HIGH", "ASSIGNED SECRETS", path, lineno, snippet)
    except Exception:
        pass
