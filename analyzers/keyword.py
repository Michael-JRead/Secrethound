"""keyword.py - secret_name = real_value, plus high-value cred/AD content shapes.

Passes per line:
  1. analyzers.credline - the single classifier for cred-bearing lines
     (netexec output, pwdump rows, ConvertTo-SecureString, plain user:pass).
     This replaces the old crude DOMAIN\\user:pass regex that flooded the
     report with icacls masks, pwdump rows and tool help-strings.
  2. a few inline-cred shapes credline doesn't own (autologon, runas, SQL
     IDENTIFIED BY, mysql -p, sshpass).
  3. generic `keyword = value` (filtered hard via analyzers.filters).
"""
import os
import re
from analyzers import filters, credline

KEY = re.compile(
    r'\b(pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|'
    r'token|auth[_-]?token|bearer|bindpw|db_pass(?:word)?|smtp_pass|ftp_pass|sa_password|'
    r'ldap_account_service_password|private[_-]?key[_-]?password|client[_-]?secret|'
    r'master[_-]?key|encryption[_-]?key|secret[_-]?key[_-]?base|jwt[_-]?secret|'
    r'connection[_-]?string|conn[_-]?str|_authtoken|requirepass|masterauth)\b'
    r'\s*[:=]\s*(.+)', re.IGNORECASE)
SKIP_LINE = re.compile(r'^\s*(#|//|\*|/\*|--\s|;)')

# code filetypes: require the value to be QUOTED (detect-secrets lesson).
_CODE_EXT = {".js", ".ts", ".py", ".rb", ".php", ".pl", ".ps1", ".java", ".go",
             ".c", ".cpp", ".cs", ".sh", ".tf", ".groovy"}

# inline-cred shapes that credline.classify does NOT already cover.
_AD = [
    # AutoLogon: matches BOTH .reg export ("DefaultPassword"="x") AND winPEAS /
    # `reg query` columnar output (DefaultPassword  REG_SZ  x).
    ("autologon password", re.compile(
        r'(?i)(?:"?DefaultPassword"?|AutoAdminLogon\s+password)\s*(?:["=:]+|\s+REG_SZ\s+)\s*["\']?([^"\'\r\n]{3,})')),
    ("SQL IDENTIFIED BY", re.compile(r'(?i)IDENTIFIED\s+BY\s+["\']([^"\']{3,})["\']')),
    ("mysql -p inline", re.compile(r'(?i)\bmysql\b[^\n]*?\s-p(\S{3,})')),
    ("sshpass -p", re.compile(r'(?i)sshpass\s+-p\s*["\']?([^"\'\s]{3,})')),
    ("runas /savecred", re.compile(r'(?i)runas\s+(?:/\w+\s+)*/user:(\S+)')),
    ("ldapsearch -w bind", re.compile(r'(?i)\bldapsearch\b[^\n]*?\s-w\s*["\']([^"\']{3,})["\']')),
    ("smbclient -U pass", re.compile(r'(?i)\bsmbclient\b[^\n]*?\s-U\s+\S+%([^\s"\']{3,})')),
    ("psexec inline", re.compile(r'(?i)\bpsexec(?:\.py)?\b[^\n]*?\s\S+/\S+:([^\s@"\']{3,})@')),
    # MSSQL setup-INI keys: SAPWD, SQLSVCPASSWORD, AGTSVCPASSWORD, RSSVCPASSWORD,
    # ISSVCPASSWORD, FTSVCPASSWORD (EscapeTwo, real exam-style ConfigurationFile.ini).
    # These slip past the generic KEY regex because `\bpassword` won't match
    # mid-word in `SQLSVCPASSWORD`.
    ("MSSQL setup key", re.compile(
        r'(?i)\b(?:SA|AGTSVC|SQLSVC|RSSVC|ISSVC|FTSVC|ASSVC)(?:PWD|PASSWORD)\s*=\s*["\']?([^"\'\s\r\n]{3,})["\']?')),
    # PHP define('CONST_*', 'value')  -  WordPress wp-config.php (DB_PASSWORD,
    # AUTH_KEY, NONCE_SALT, etc.) plus any CONST whose name ends in PASSWORD /
    # SECRET / KEY / TOKEN. `\bpass(word)?` won't catch DB_PASSWORD because
    # the boundary fails between `B` and `P`.
    ("PHP define secret", re.compile(
        r"(?i)\bdefine\s*\(\s*['\"]([A-Z][A-Z0-9_]*(?:PASSWORD|PASS|PWD|SECRET|KEY|SALT|TOKEN))['\"]"
        r"\s*,\s*['\"]([^'\"\r\n]{3,})['\"]")),
    # Plain $varEndingInPwdLike = "X":  Joomla $password / $smtppass, MediaWiki
    # $wgDBpassword / $wgSecretKey, Drupal $databases array values, any $\w*
    # ending in password/pass/pwd/secret/salt/authtoken. We deliberately omit
    # $key/$token (too generic - matches encryption-key config vars).
    ("PHP var secret", re.compile(
        r"(?i)\$\w*(?:password|passwd|pwd|secret|salt|authtoken|smtppass|ftppass|dbpass)\b"
        r"\s*=\s*['\"]([^'\"\r\n]{3,})['\"]")),
    # PHP nested-array string key: 'password' => 'X', 'db_passwd' => 'X', "PWD" => "X"
    # (Koken database.php, OpenAdmin $ona_contexts, generic Phinx/Slim configs)
    ("PHP array secret", re.compile(
        r"(?i)['\"](?:db_)?(?:password|passwd|pwd|secret|salt|smtppass)['\"]"
        r"\s*=>\s*['\"]([^'\"\r\n]{3,})['\"]")),
    # ADO.NET / php connection-string keyword: PWD=X or UID=>X
    ("conn-string keyword", re.compile(
        r"(?i)['\"]?(?:PWD|PASSWORD|UID|USER\s*ID)['\"]?\s*=>?\s*['\"]([^'\"\r\n]{3,})['\"]")),
    # MongoDB BSON shell output: { ..., "username" : "X", "password" : "Y" }
    ("MongoDB BSON", re.compile(
        r'"username"\s*:\s*"([^"]{1,40})"[^}]{0,200}?"password"\s*:\s*"([^"]{3,80})"')),
    # tomcat-users.xml <user username="X" password="Y" roles="Z"/>  - capture both
    # user and pw, plus roles so the hint distinguishes RCE-path (manager-script /
    # admin-gui) from read-only.
    ("tomcat-users", re.compile(
        r'(?i)<user\s+(?=[^>]*\busername\s*=\s*["\']([^"\']{1,40})["\'])'
        r'(?=[^>]*\bpassword\s*=\s*["\']([^"\']{1,80})["\'])'
        r'(?:[^>]*\broles\s*=\s*["\']([^"\']{0,200})["\'])?[^>]*/?>')),
    # FileZilla / similar: <Pass encoding="base64">b64</Pass>
    ("FileZilla pass", re.compile(
        r'(?i)<Pass\s+encoding\s*=\s*["\']base64["\']\s*>([A-Za-z0-9+/=]{4,200})</Pass>')),
    # Windows unattend.xml: <Value>X</Value> inside a Password/AdministratorPassword
    # where <PlainText>true</PlainText> appears on the same line OR within ~80
    # chars. (Plaintext branch only - the base64-UTF16LE branch needs proper XML
    # context tracking and lives in a separate analyzer.)
    ("unattend plaintext", re.compile(
        r'(?i)<Password>\s*<Value>([^<\r\n]{3,})</Value>\s*<PlainText>\s*true\s*</PlainText>')),
    # Jenkins encrypted blob in credentials.xml - cannot decrypt without master.key
    # + hudson.util.Secret (the full chain), but flag the file as a high-value
    # target and point to the offline decoder.
    ("Jenkins enc blob", re.compile(
        r'\{AQAAA[A-Za-z0-9+/=]{20,}\}')),
]


def _value_ok(value, line):
    cv = value.strip().strip("'\"")
    if len(cv) < 3 or len(cv) > 200:
        return False
    if filters.is_placeholder(value) or filters.is_known_example(value):
        return False
    if filters.is_code_not_literal(value, line):
        return False
    return True


# netexec / crackmapexec text-log service line:  PROTO  IP  PORT  HOSTNAME  [..]
# we learn host<->service so chains target the REAL ip (not <DC-IP>); the cred on
# the same line is still owned by credline below (we fall through, never claim).
_NXC_SVC = re.compile(r'^(SMB|WINRM|LDAPS?|MSSQL|SSH|FTP|RDP|WMI|NFS|VNC)\s+'
                      r'(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,5})\s+(\S+)')
_NXC_PROTO = {"smb": "smb", "winrm": "winrm", "ldap": "ldap", "ldaps": "ldaps",
              "mssql": "mssql", "ssh": "ssh", "ftp": "ftp", "rdp": "rdp",
              "wmi": "smb", "nfs": "nfs", "vnc": "vnc"}


def _learn_nxc_service(line, path, store, seen):
    m = _NXC_SVC.match(line)
    if not m:
        return
    proto = m.group(1).lower()
    svc = _NXC_PROTO.get(proto, proto)
    ip, port, hostname = m.group(2), int(m.group(3)), m.group(4)
    key = (svc, ip)
    if key in seen:
        return
    seen.add(key)
    from analyzers.ingest.evidence import Evidence
    if hostname and hostname[0].isalnum():
        store.learn_host(ip=ip, names=[hostname])
    store.add(Evidence(kind="service", host=ip, port=port, service=svc, source=path))
    if svc in ("ldap", "ldaps"):     # LDAP exposed -> Domain Controller
        store.add(Evidence(kind="host", host=ip, fact="dc", source=path))


def analyze(path, report, store=None):
    ext = os.path.splitext(path)[1].lower()
    require_quote = ext in _CODE_EXT
    seen_svc = set()
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if SKIP_LINE.match(line):
                    continue

                # ---- pass 0: learn netexec/cme service lines (no claim) ----
                if store is not None and _NXC_SVC.match(line):
                    _learn_nxc_service(line, path, store, seen_svc)
                    # fall through: credline may still pull a cred off this line

                # ---- pass 1: the credential-line classifier ----
                c = credline.classify(line)
                if c and c.kind in ("cred", "failed"):
                    who = (c.user or "<user>")
                    tag = " (FAILED auth)" if c.kind == "failed" else ""
                    sev = "HIGH" if c.kind == "failed" else "CRITICAL"
                    label = (f"{c.note}: {c.password}" if c.note == "PowerShell SecureString"
                             else f"{who}:{c.password}{tag}")
                    report.add(sev, "CRED PAIRS", path, lineno, label,
                               f"netexec smb <DC-IP> -u '{who}' -p '{c.password}' -k")
                    if store is not None:
                        from analyzers.ingest.evidence import Evidence
                        store.add(Evidence(kind="plaintext", user=c.user,
                                           plaintext=c.password, domain=c.domain,
                                           source=path, line=lineno))
                    continue
                if c and c.kind == "pwdump":
                    continue          # handled (user-bound) by patterns.py

                # ---- pass 2: inline-cred shapes ----
                hit = False
                for name, rx in _AD:
                    am = rx.search(line)
                    if not am:
                        continue
                    # tomcat-users: user+pass+roles -> RCE-aware severity
                    if name == "tomcat-users":
                        u, p, roles = am.group(1), am.group(2), (am.group(3) or "")
                        if not p or filters.is_placeholder(p):
                            continue
                        rce = any(r in roles.lower() for r in
                                  ("manager-script", "manager-jmx", "admin-gui", "admin-script"))
                        sev = "CRITICAL" if rce else "HIGH"
                        cat = "CRED PAIRS" if rce else "ASSIGNED SECRETS"
                        hint = (f"tomcat WAR-deploy RCE: curl --upload-file shell.war "
                                f"-u '{u}:{p}' 'http://<host>:8080/manager/text/deploy?path=/shell'"
                                if rce else
                                f"tomcat login: u={u} p={p}; check /manager /host-manager")
                        report.add(sev, cat, path, lineno, f"tomcat user '{u}':{p}" +
                                   (f"  [{roles[:40]}]" if roles else ""), hint=hint)
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # FileZilla base64 obfuscation -> decode inline
                    if name == "FileZilla pass":
                        import base64 as _b64
                        try:
                            pw = _b64.b64decode(am.group(1), validate=True).decode("utf-8")
                        except Exception:
                            pw = am.group(1) + " (base64 - decode by hand)"
                        if filters.is_placeholder(pw):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"FileZilla saved password: {pw}",
                                   hint="FileZilla base64 obfuscation - reuse directly")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # Jenkins encrypted blob: flag the file (cannot decrypt without
                    # master.key + hudson.util.Secret) and point to the offline chain
                    if name == "Jenkins enc blob":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "Jenkins credentials.xml encrypted blob",
                                   hint="offline decrypt: hoto/jenkins-credentials-decryptor -m secrets/master.key "
                                   "-s secrets/hudson.util.Secret -c credentials.xml")
                        hit = True
                        break
                    # PHP define('CONST', 'value') -> 2-group capture
                    if name == "PHP define secret":
                        const, val = am.group(1), am.group(2)
                        if not val or filters.is_placeholder(val) or filters.is_code_not_literal(val, line):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"{const}: {val}",
                                   hint="PHP define() literal - reuse directly")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val, source=path, line=lineno))
                        hit = True
                        break
                    # default 1-group capture
                    val = am.group(1)
                    if not val or filters.is_placeholder(val) or filters.is_code_not_literal(val, line):
                        continue
                    report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                               f"{name}: {val}",
                               hint="plaintext credential in script/config - reuse directly")
                    if store is not None:
                        from analyzers.ingest.evidence import Evidence
                        store.add(Evidence(kind="plaintext", plaintext=val, source=path, line=lineno))
                    hit = True
                    break
                if hit:
                    continue

                # ---- pass 3: generic keyword = value ----
                if credline.looks_like_noise(line):
                    continue
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
