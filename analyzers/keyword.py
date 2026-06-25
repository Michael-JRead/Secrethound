"""keyword.py - secret_name = real_value, with false-positive filtering."""
import re

KEY = re.compile(
    r'\b(pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|'
    r'token|auth[_-]?token|bearer|bindpw|db_pass(?:word)?|smtp_pass|ftp_pass|sa_password|'
    r'ldap_account_service_password|private[_-]?key[_-]?password|client[_-]?secret|'
    r'connection[_-]?string|conn[_-]?str)\b'
    r'\s*[:=]\s*(.+)', re.IGNORECASE)
NOISE_VALUE = re.compile(
    r'^["\']?\s*(|none|null|false|true|0|1|""|\'\'|changeme|change_me|example|password|'
    r'xxx+|<[^>]+>|\{\{.*|\$\{.*|%[sd].*|getpass\b.*|os\.environ.*|conf\[.*|self\..*|'
    r'input\(.*|prompt.*|request\..*|args\..*|options\..*)\s*["\']?\s*$', re.IGNORECASE)
SKIP_LINE = re.compile(r'^\s*(#|//|\*|/\*|--\s|;)')


def analyze(path, report):
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if SKIP_LINE.match(line):
                    continue
                m = KEY.search(line)
                if not m:
                    continue
                value = re.split(r'\s+[#;]\s', m.group(2).strip())[0].strip()
                if not value or NOISE_VALUE.match(value):
                    continue
                cv = value.strip("'\"")
                if len(cv) < 3:
                    continue
                if re.search(r'[()\[\]{}]|\.encode|\.lower|\.get|callback|=|,$|:$|\bNone\b|\bself\b', value):
                    continue
                snippet = line.strip()
                if len(snippet) > 130:
                    snippet = snippet[:130] + "..."
                report.add("HIGH", "ASSIGNED SECRETS", path, lineno, snippet)
    except Exception:
        pass
