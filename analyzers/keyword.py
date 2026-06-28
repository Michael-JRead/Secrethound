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
    # MongoDB BSON shell output: { ..., "username" : "X", "password" : "Y" }
    ("MongoDB BSON", re.compile(
        r'"username"\s*:\s*"([^"]{1,40})"[^}]{0,200}?"password"\s*:\s*"([^"]{3,80})"')),
    # Legacy Windows LAPS cleartext attribute: ms-Mcs-AdmPwd: <pw>
    # (post-decryption read; Streamio / Outdated / Rebound modern fixture)
    ("LAPS ms-Mcs-AdmPwd", re.compile(
        r'(?i)\bms-mcs-admpwd\s*:\s*(?!\s)([^\r\n]{3,80})')),
    # Windows LAPS v2 cleartext-after-decrypt output: 'Password : <pw>' under
    # 'ComputerName' / 'Account' block produced by Get-LapsADPassword -AsPlainText
    ("LAPS v2 cleartext", re.compile(
        r'(?im)^\s*Password\s*:\s*([^\r\n]{6,80})$')),
    # gMSA managed password LDIF attribute (base64 blob; flag, don't try to decode).
    # The classic LDIF `::` prefix indicates base64; gMSADumper does the NTLM parse.
    ("gMSA ManagedPassword", re.compile(
        r'(?i)\bmsDS-ManagedPassword\b\s*::\s*([A-Za-z0-9+/=]{40,})')),
    # Shadow credentials marker - msDS-KeyCredentialLink writes are non-destructive
    # but high-signal (precondition for PKINIT NT-hash recovery via Certipy).
    ("Shadow credentials", re.compile(
        r'(?i)msDS-KeyCredentialLink\b|Adding Key Credential with device ID')),
    # Certipy `Got hash for 'user@DOM': LM:NT` shadow-creds / PKINIT output.
    # We DON'T put this in `_AD` to keep the unconditional CRED-pair routing
    # below clean; instead it's split out so we can emit user-bound NT.
    ("Certipy got-hash", re.compile(
        r"(?i)\b(?:Got|NT)\s+hash\s+for\s+['\"]?([^\s'\":@]{1,40})(?:@[^\s'\"]+)?['\"]?\s*:\s*"
        r"(?:([a-f0-9]{32}):)?([a-f0-9]{32})\b")),
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
    # ---- iter-6 INTEL markers (not raw creds; high-signal next-step pointers) ----
    # AD CS ESC vuln from certipy/certify output. Broad match here; the dispatch
    # branch requires an ADCS context word on the line to avoid 'ESC1' FPs.
    ("ADCS ESC", re.compile(r'\bESC(1[0-6]|[1-9])\b')),
    # RBCD: the attribute name is unique enough to flag unconditionally.
    ("RBCD marker", re.compile(r'(?i)\bmsDS-AllowedToActOnBehalfOfOtherIdentity\b')),
    # BloodHound ACL edge, arrow form: name --[WriteOwner]--> target (distinctive).
    # A real edge always points at a destination principal; require a node token
    # after the arrow so prose that merely names the notation (e.g. a markdown doc:
    # "reading `--[GenericAll]-->` style edges") doesn't FP.
    ("BloodHound ACL edge", re.compile(
        r'--\[(WriteDacl|WriteOwner|GenericAll|GenericWrite|ForceChangePassword|'
        r'AddMember|Owns|AllExtendedRights|AddKeyCredentialLink|ReadGMSAPassword|'
        r'ReadLAPSPassword|AddSelf|WriteSPN)\]-->\s*["\']?[A-Za-z0-9][\w$.@-]+')),
    # WSUS abuse tool invocation.
    ("WSUS abuse", re.compile(r'(?i)\bSharpWSUS(?:\.exe)?\s+(?:create|approve|check|delete)\b')),
    # DPAPI masterkey recovery output / mimikatz dpapi module.
    ("DPAPI masterkey", re.compile(
        r'(?i)dpapi::masterkey|\[masterkey\]\s*[a-f0-9]{32,}|guidMasterKey')),
    # ADO.NET connection string: connectionString="...;User ID=x;Password=y;"
    # (Mantis Orchard web.config). Captures the whole value; branch parses it.
    ("ADO connectionString", re.compile(
        r'(?i)connectionString\s*=\s*["\']([^"\'\r\n]{8,400})["\']')),
    # ---- iter-7 round-2 completeness adds (from workflow's missing-class list) ----
    # SQL INSERT cred row: INSERT INTO users (..., username, ..., password, ...)
    # VALUES (..., 'X', ..., '$2y$10$...', ...); also pg/MySQL COPY/dump format.
    # Captures bcrypt/MD5/plain into PASSWORD HASHES.
    ("SQL INSERT cred row", re.compile(
        r"(?i)INSERT\s+INTO\s+\W?(?:users?|members?|accounts?|admins?|"
        r"login|customers?|employees?)[^()]*\([^)]*\bpassword\b[^)]*\)\s*VALUES\s*\(([^)]+)\)")),
    # SNMP community strings: rocommunity/rwcommunity + value (+ optional ACL).
    # Direct enum vector - rwcommunity = direct foothold on the OSCP exam.
    ("SNMP community", re.compile(
        r'(?i)^\s*(rocommunity|rwcommunity|rocommunity6|rwcommunity6)\s+'
        r'([^\s#]{3,60})(?:\s+([^\s#]+))?')),
    # docker-compose / k8s / .env environment variables that look credential-y.
    # MYSQL_ROOT_PASSWORD, POSTGRES_PASSWORD, REDIS_PASSWORD etc.
    ("docker env secret", re.compile(
        r'(?i)\b(MYSQL_(?:ROOT_)?PASSWORD|POSTGRES_(?:DB_)?PASSWORD|MARIADB_(?:ROOT_)?PASSWORD|'
        r'MONGO(?:DB)?_(?:INITDB_)?(?:ROOT_)?PASSWORD|REDIS_PASSWORD|RABBITMQ_(?:DEFAULT_)?PASS|'
        r'ELASTIC_PASSWORD|MINIO_(?:ROOT_)?(?:USER|PASSWORD)|GF_SECURITY_ADMIN_PASSWORD|'
        r'KEYCLOAK_ADMIN_PASSWORD|HASURA_GRAPHQL_ADMIN_SECRET|'
        r'SMTP_(?:PASSWORD|PASS|AUTH_PASSWORD))\s*[:=]\s*["\']?([^"\'\r\n]{3,80})["\']?')),
    # PowerShell PSReadLine history: cmdkey /add:host /user:DOM\u /pass:X
    # (one of the highest-value OSCP+ history-file lines).
    # `\w` doesn't include '\' so we use `[^\s/]+` for the inter-flag tokens.
    ("cmdkey history", re.compile(
        r'(?i)\bcmdkey(?:\.exe)?\s+(?:/[^\s/]+\s+)*/pass(?:word)?\s*[:=]\s*([^\s/]{3,80})')),
    # ASP.NET machineKey - both halves are crackable hex for ViewState forgery.
    ("ASP.NET machineKey", re.compile(
        r'(?i)<machineKey\b[^>]*?\bvalidationKey\s*=\s*["\']([A-F0-9]{16,})["\'][^>]*?'
        r'\bdecryptionKey\s*=\s*["\']([A-F0-9]{16,})["\']')),
    # SCCM Network Access Account (NAA) is two-line - handled by
    # _multiline_passes() below, not the line-by-line _AD loop.
    # LSA-secrets section in secretsdump (machine account + LSA SCM service creds)
    ("LSA secret", re.compile(
        r'(?i)\$MACHINE\.ACC\s*:\s*([a-f0-9]{32}:[a-f0-9]{32})|'
        r'^SCM\s*:\s*\{[^}]*\}\s*:\s*(\S+):(\S+)', re.MULTILINE)),
    # ---- iter-8 round-1 completeness adds ----
    # Certipy 'find -vulnerable' template block markers (per-ESC verbose dump).
    # The block carries 'Template Name : <name>' + 'Vulnerabilities : ESC<n>'
    # + 'Enrollment Rights : <principal list>' - we capture the template name +
    # ESC number for a precise per-template finding.
    ("Certipy template ESC", re.compile(
        r'(?i)Template\s+Name\s*:\s*(\S[^\r\n]{0,60})[\s\S]{0,800}?'
        r'Vulnerabilit(?:y|ies)\s*:\s*([^\r\n]{1,120})')),
    # PostgreSQL pg_hba.conf 'trust' / 'md5' / 'scram-sha-256' / 'password' lines:
    # `local all all trust` means anyone can become any DB user from localhost
    # without a password. 'host all all 0.0.0.0/0 trust' = unauth remote DB.
    ("pg_hba auth method", re.compile(
        r'^\s*(local|host|hostssl|hostnossl|hostgssenc|hostnogssenc)\s+'
        r'(\S+)\s+(\S+)\s+(?:(\S+)\s+)?(trust|password|reject)\b', re.MULTILINE)),
    # MySQL/MariaDB option file [client] / [mysql] / [mysqldump] sections with
    # plaintext password=... (.my.cnf, /etc/mysql/debian.cnf).
    ("mysql client opt", re.compile(
        r'(?im)^\s*password\s*=\s*["\']?([^"\'#\r\n]{3,80})["\']?\s*$')),
    # Redis requirepass / masterauth in conf - already partially handled by KEY,
    # but here as a dedicated rule with a service-bound hint.
    ("redis requirepass", re.compile(
        r'(?im)^\s*(requirepass|masterauth)\s+([^\s#]{3,80})')),
    # /etc/sudoers NOPASSWD entry: gives `user` direct root via the named cmd
    # without a password - a single-line privesc primitive.
    ("sudoers NOPASSWD", re.compile(
        r'(?i)^(\S+)\s+\S+\s*=\s*\([^)]*\)\s*NOPASSWD\s*:\s*(\S[^\r\n]{0,200})', re.MULTILINE)),
    # Writable cron entry pointing at a script - the cron line + the script's
    # writability is the privesc. Filename gate is applied in the dispatch
    # branch (only fires when path looks like crontab / /etc/cron* / /var/spool/cron).
    ("cron script ref", re.compile(
        r'^(?:[\s/*0-9,-]+\s+){4,5}(?:[\w-]+\s+)?'
        r'((?:/[\w./-]+)(?:\.sh|\.py|\.pl|\.rb|\.bash))\b', re.MULTILINE)),
    # Hashcat potfile line (hash:plain). Only fired when the path looks like a
    # potfile (extension/filename gate is in the dispatch branch) AND the hash
    # half starts with a recognised hash prefix ($1$, $2y$, $5$, $6$, $apr1$,
    # $krb5..., $keepass$, $pwsafe$, $sntp-ms$, $DCC2$, $S$, $P$/$H$, $argon2,
    # etc.) or is exactly 32/40 hex - the bare-shape match alone was matching
    # every `attribute: value` LDIF line.
    ("hashcat potfile", re.compile(
        r'^(\$(?:1|2[aby]|5|6|y|argon2[id]+|apr1|S|P|H|NT|DCC2|krb5(?:tgs|asrep|pa)|'
        r'keepass|pwsafe|sntp-ms|ansible|pkcs12|ANSIBLE_VAULT)\$\S{6,}|'
        r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{60}):([^\r\n:]{3,100})$',
        re.MULTILINE)),
    # John's john --show output and pot lines: hash:plain too. Pot lines start
    # with $NT$, $krb5tgs$, etc. The plain half must NOT be hex-only or contain
    # a hash-prefix '$' (which would indicate the line is still inside the hash).
    ("john pot", re.compile(
        r'^(\$NT\$[a-fA-F0-9]{32}|\$krb5(?:tgs|asrep|pa)\$\S{20,}):([^\r\n\$:]{3,80})$',
        re.MULTILINE)),
    # AWS credentials INI shape: `[profile]\naws_access_key_id = AKIA...\n
    # aws_secret_access_key = ...`. The secret already matches our 'AWS secret'
    # rule; here we flag the SESSION TOKEN line too.
    ("AWS session token", re.compile(
        r'(?i)\baws_session_token\s*=\s*([A-Za-z0-9/+=]{100,})')),
    # GCP service-account JSON keys: 'private_key' field as PEM blob marker.
    ("GCP service account", re.compile(
        r'"type"\s*:\s*"service_account"[\s\S]{0,200}?"private_key_id"\s*:\s*"([a-f0-9]{40})"')),
    # Kubeconfig bearer token: `token: <jwt>` under user.token, or
    # `client-certificate-data: <b64>` + `client-key-data: <b64>` under user.
    ("kubeconfig token", re.compile(
        r'(?im)^\s*token\s*:\s*([A-Za-z0-9._-]{32,})\s*$')),
    # Terraform state with "sensitive": true output keeps the plaintext value.
    ("Terraform sensitive", re.compile(
        r'"sensitive"\s*:\s*true[\s\S]{0,300}?"value"\s*:\s*"([^"]{3,200})"')),
    # Azure CLI accessTokens.json shape - look for the bearer access token.
    ("Azure access token", re.compile(
        r'"accessToken"\s*:\s*"(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_.-]+\.[A-Za-z0-9_-]+)"')),
    # Supervisord inet_http_server creds (rare, but a real OSCP-flavored box):
    # `[inet_http_server]\nport=...\nusername=admin\npassword=...`
    ("supervisord inet creds", re.compile(
        r'(?is)\[inet_http_server\][\s\S]{0,500}?username\s*=\s*(\S+)[\s\S]{0,200}?password\s*=\s*(\S+)')),
    # asterisk manager.conf - VoIP boxes (Beep-like)
    ("asterisk manager", re.compile(
        r'(?is)^\s*\[([\w_-]+)\]\s*[\r\n]+(?:[^\r\n]*[\r\n]+)*?secret\s*=\s*([^\s#\r\n]{3,80})', re.MULTILINE)),
    # Veeam VBR plaintext-fielded creds in stored sessions / backup .vbm xml
    ("Veeam creds", re.compile(
        r'(?is)<Cred[^>]*\sUsername\s*=\s*"([^"]{1,80})"[^>]*\sPassword\s*=\s*"([^"]{3,200})"')),
    # GitHub Actions secret REFERENCE - the secret itself is in vault, but the
    # presence of `${{ secrets.X }}` in a checked-out workflow tells the operator
    # which CI secret name to target.
    ("GH Actions secret ref", re.compile(
        r'\$\{\{\s*secrets\.(\w+)\s*\}\}')),
    # Confluence/Atlassian seraph + LDAP password fields in atlassian-user.xml
    ("atlassian secret", re.compile(
        r'(?i)<password>([^<\r\n]{3,80})</password>')),
    # PowerShell SecureString export blob (Export-Clixml of a PSCredential):
    # `<SS N="Password">01000000d08c9ddf01...</SS>`
    ("PSCredential SS blob", re.compile(
        r'<SS\s+N\s*=\s*"Password"\s*>([0-9a-f]{40,})</SS>')),
    # OpenVPN auth-user-pass file (two lines: user, pass)
    ("ovpn auth-user-pass", re.compile(
        r'(?im)^\s*auth-user-pass\s+(\S+)\s*$')),
    # WireGuard PrivateKey in [Interface]
    ("WireGuard PrivateKey", re.compile(
        r'(?im)^\s*PrivateKey\s*=\s*([A-Za-z0-9+/]{42,44}=)\s*$')),
    # NetSCREEN / Cisco IOS enable secret 5/7
    ("Cisco enable secret", re.compile(
        r'(?i)\benable\s+secret\s+(\d)\s+([\S]{6,200})')),
    # JuicyPotato / Print Spooler / SeImpersonate output that lists a token to
    # impersonate. Intel-only.
    ("token impersonation", re.compile(
        r'(?i)SeImpersonatePrivilege|SeAssignPrimaryToken|JuicyPotato\.exe|PrintSpoofer\.exe|GodPotato\.exe|RoguePotato\.exe')),
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


_SCCM_NAA_MULTI = re.compile(
    r'(?i)NetworkAccess(?:Account|Username)\s*[:=]\s*(\S+)[\s\S]{0,400}?'
    r'NetworkAccessPassword\s*[:=]\s*([^\r\n]{3,80})'
)


def _multiline_passes(path, report, store):
    """File-level passes that need multi-line context (SCCM NAA blocks span
    two lines; can't be matched line-by-line)."""
    try:
        with open(path, "r", errors="ignore") as fh:
            text = fh.read(50000)
    except OSError:
        return
    for m in _SCCM_NAA_MULTI.finditer(text):
        u, p = m.group(1).strip(), m.group(2).strip()
        if filters.is_placeholder(p):
            continue
        lineno = text[: m.start()].count("\n") + 1
        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                   f"SCCM NAA: {u}:{p}",
                   hint="Network Access Account - typically a domain account; reuse for SMB/WinRM")
        if store is not None:
            from analyzers.ingest.evidence import Evidence
            store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=lineno))


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
                # iter-7 (round 2): doc files (hardening guides, cheatsheets)
                # teach AutoLogon REG_SZ syntax and show 'Strong Passwords'
                # examples - skip all the inline-cred patterns here.
                _is_doc = filters.is_doc_file(path)
                for name, rx in _AD:
                    am = rx.search(line)
                    if not am:
                        continue
                    # autologon password in doc files is teaching content, not loot.
                    if _is_doc and name in ("autologon password",
                                            "SQL IDENTIFIED BY",
                                            "sshpass -p",
                                            "mysql -p inline"):
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
                    # Shadow credentials: msDS-KeyCredentialLink write or Certipy
                    # output. Intel-only (the NT hash recovered THROUGH this path
                    # is captured by the 'Certipy got-hash' rule below).
                    if name == "Shadow credentials":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "Shadow Credentials marker (msDS-KeyCredentialLink)",
                                   hint="certipy-ad shadow auto -account <target> -u <user>@<dom> -p <pw> "
                                   "-> PKINIT -> NT hash via getnthash / U2U")
                        hit = True
                        break
                    # Certipy 'Got hash for X: LM:NT' -> CRITICAL user-bound NT hash
                    if name == "Certipy got-hash":
                        user, lm, nt = am.group(1), (am.group(2) or ""), am.group(3)
                        if not nt or filters.is_blank_hash(nt):
                            hit = True
                            break
                        report.add("HIGH", "PASSWORD HASHES", path, lineno,
                                   f"NTLM (NT) {user}: {nt}",
                                   hint=f"PtH: netexec smb <DC-IP> -u '{user}' -H {nt}  |  crack: hashcat -m 1000 {nt} rockyou.txt")
                        # also feed the global HASHES list so --hashes file picks it up
                        from analyzers.patterns import HASHES
                        HASHES.append(("1000", "NTLM", nt, path, lineno))
                        hit = True
                        break
                    # LAPS cleartext (ms-Mcs-AdmPwd / Windows-LAPS) -> CRITICAL local admin pw
                    if name in ("LAPS ms-Mcs-AdmPwd", "LAPS v2 cleartext"):
                        pw = am.group(1).strip()
                        if filters.is_placeholder(pw) or len(pw) < 6:
                            hit = True
                            break
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"LAPS local admin password: {pw}",
                                   hint="local admin: netexec smb <host> -u Administrator -p '" + pw +
                                   "' --local-auth  | or evil-winrm -i <host> -u Administrator -p '" + pw + "'")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user="Administrator",
                                               plaintext=pw, source=path, line=lineno))
                        hit = True
                        break
                    # gMSA blob marker - cannot decode without bloodyAD/gMSADumper auth
                    if name == "gMSA ManagedPassword":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "gMSA msDS-ManagedPassword blob",
                                   hint="gMSADumper.py -u <user> -p <pw> -d <dom> -l <dc>  (RetrievePrincipal right needed)")
                        hit = True
                        break
                    # ---- iter-6 INTEL markers ----
                    # Iter-7: doc/cheatsheet/tutorial files (`pentest-cheatsheet.md`,
                    # `AD-hardening-guide.md`, `bloodhound-acl-edges.md`,
                    # `kerberoasting-explained.txt`) are designed to TEACH these
                    # primitives, so the markers appear in prose constantly. The
                    # operator's loot never lives in those - we suppress intel
                    # detectors on them entirely.
                    if name in ("ADCS ESC", "RBCD marker", "BloodHound ACL edge",
                                "WSUS abuse", "DPAPI masterkey") and filters.is_doc_file(path):
                        continue
                    # AD CS ESC#: must look like ACTUAL certipy / certify output
                    # ('Vulnerabilities:', '[!] ESC1', 'Template Name :',
                    # 'Certipy v4...', 'EnableTemplate', 'ManageCA :', etc.),
                    # NOT a markdown bullet from a docs cheatsheet ('- ESC1:
                    # enrollee-supplies-subject ...'). Iter-7 FP audit: 11 doc
                    # FPs killed by this stricter gate.
                    if name == "ADCS ESC":
                        is_markdown_bullet = re.match(r'^\s*[-*]\s+ESC\d', line)
                        ctx = re.search(
                            r'(?i)Vulnerabilit(?:y|ies)\s*:|Certipy\s+v\d|certipy-ad|certify\.exe|'
                            r'\[\s*[!+*]\s*\]\s*ESC\d|Template\s+Name\s*:|EnableTemplate|'
                            r'Manage[CC]A\s*:|Manage[Cc]ertificates|ESC\d\s*\(|'
                            r'Enrollee\s+Supplies\s+Subject|Client\s+Authentication\s*:\s*True|'
                            r'Enrollment\s+Rights', line)
                        if is_markdown_bullet or not ctx:
                            continue
                        esc = am.group(0).upper()
                        report.add("HIGH", "RECON", path, lineno,
                                   f"AD CS {esc} vulnerable template / right",
                                   hint=f"certipy-ad req ... ({esc}); then certipy-ad auth -pfx <out>.pfx -> NT hash / TGT")
                        hit = True
                        break
                    if name == "RBCD marker":
                        report.add("HIGH", "RECON", path, lineno,
                                   "RBCD attribute (msDS-AllowedToActOnBehalfOfOtherIdentity)",
                                   hint="impacket-rbcd -delegate-from <ctrl> -delegate-to <target$> -action write ...; "
                                   "then getST.py -impersonate Administrator")
                        hit = True
                        break
                    if name == "BloodHound ACL edge":
                        # iter-7: even with a node-token after the arrow, lines
                        # inside backticks ('reading `--[GenericAll]-->` style')
                        # or wrapped in inline-code/quotes are explanatory prose.
                        if re.search(r'`[^`]*--\[[^`]+\]-->[^`]*`', line):
                            continue
                        edge = am.group(1)
                        report.add("HIGH", "RECON", path, lineno,
                                   f"BloodHound ACL edge: {edge} (privilege-escalation path)",
                                   hint="abuse with bloodyAD / PowerView / dacledit per edge; shortest path to DA")
                        hit = True
                        break
                    if name == "WSUS abuse":
                        report.add("HIGH", "RECON", path, lineno,
                                   "WSUS update-push abuse (SharpWSUS)",
                                   hint="LAB-ONLY for the exam unless the WSUS host is in scope - signed-binary update -> SYSTEM on client/DC")
                        hit = True
                        break
                    if name == "DPAPI masterkey":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "DPAPI masterkey material",
                                   hint="impacket-dpapi masterkey -file <mk> -sid <SID> -password <pw>  (or -rpc on a box you own)")
                        hit = True
                        break
                    # ---- iter-7 round-2 completeness handlers ----
                    if name == "SQL INSERT cred row":
                        # capture group is the VALUES (...) tuple; extract every
                        # quoted value and look for a bcrypt/MD5/plain hash.
                        vals = re.findall(r"['\"]([^'\"]{2,80})['\"]", am.group(1))
                        # try to find a hash-shaped value; otherwise emit as cred
                        hashy = next((v for v in vals
                                      if re.match(r'^\$2[aby]\$|^\$1\$|^\$6\$|^\$5\$|'
                                                  r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|'
                                                  r'^[a-f0-9]{60}$|^\$apr1\$', v)), None)
                        usery = next((v for v in vals if re.match(r'^[A-Za-z][\w@.-]{1,40}$', v) and len(v) <= 40), None)
                        if hashy:
                            report.add("HIGH", "PASSWORD HASHES", path, lineno,
                                       f"SQL dump user: {usery or '<unknown>'}  hash: {hashy[:60]}",
                                       hint="check hashid then hashcat -m <mode>; common: bcrypt -m 3200, md5 -m 0")
                            from analyzers.patterns import HASHES
                            if hashy.startswith("$2"): HASHES.append(("3200", "bcrypt", hashy, path, lineno))
                            elif hashy.startswith("$1$"): HASHES.append(("500", "md5crypt", hashy, path, lineno))
                            elif hashy.startswith("$6$"): HASHES.append(("1800", "sha512crypt", hashy, path, lineno))
                            elif hashy.startswith("$apr1$"): HASHES.append(("1600", "apr1", hashy, path, lineno))
                            elif len(hashy) == 32: HASHES.append(("0", "MD5", hashy, path, lineno))
                        hit = True
                        break
                    if name == "SNMP community":
                        kind, comm, source = am.group(1), am.group(2), (am.group(3) or "")
                        if filters.is_placeholder(comm):
                            continue
                        rw = kind.lower().startswith("rwcommunity")
                        sev = "CRITICAL" if rw else "HIGH"
                        report.add(sev, "ASSIGNED SECRETS", path, lineno,
                                   f"SNMP {kind}: {comm}" + (f"  ({source})" if source else ""),
                                   hint=("snmpwalk -v2c -c '" + comm + "' <host>  " +
                                         ("(read-WRITE - snmpset for direct config tampering)" if rw
                                          else "(read-only enum: walk full tree)")))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=comm, source=path, line=lineno))
                        hit = True
                        break
                    if name == "docker env secret":
                        var, val = am.group(1), am.group(2).strip()
                        if filters.is_placeholder(val) or filters.is_known_example(val):
                            continue
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"{var}: {val}",
                                   hint="container/orchestration secret - reuse directly against the service")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val, source=path, line=lineno))
                        hit = True
                        break
                    if name == "cmdkey history":
                        pw = am.group(1).strip()
                        if filters.is_placeholder(pw):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"cmdkey history password: {pw}",
                                   hint="typed in PowerShell - reuse against the host in the same cmdkey line / via SMB")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=pw, source=path, line=lineno))
                        hit = True
                        break
                    if name == "ASP.NET machineKey":
                        vk, dk = am.group(1), am.group(2)
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"ASP.NET machineKey  validationKey={vk[:32]}{'...' if len(vk)>32 else ''} "
                                   f"decryptionKey={dk[:32]}{'...' if len(dk)>32 else ''}",
                                   hint="ViewState forgery: ysoserial.net + these keys -> RCE (CVE-2017-9248-class)")
                        hit = True
                        break
                    # SCCM NAA handled by _multiline_passes() (two-line block)
                    if name == "LSA secret":
                        if am.group(1):  # $MACHINE.ACC : LM:NT
                            pair = am.group(1)
                            nt = pair.split(":")[1]
                            report.add("HIGH", "PASSWORD HASHES", path, lineno,
                                       f"NTLM (NT) $MACHINE.ACC: {nt}",
                                       hint=f"machine account hash - silver/golden-ticket primitive: nxc smb <dc> -u 'HOSTNAME$' -H {nt}")
                            from analyzers.patterns import HASHES
                            HASHES.append(("1000", "NTLM", nt, path, lineno))
                        elif am.group(2) and am.group(3):
                            u, p = am.group(2), am.group(3)
                            report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                       f"LSA SCM service cred: {u}:{p}",
                                       hint="service account password recovered from LSA secrets - reuse against the host")
                            if store is not None:
                                from analyzers.ingest.evidence import Evidence
                                store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=lineno))
                        hit = True
                        break
                    # ---- iter-8 round-1 dispatch ----
                    if name == "Certipy template ESC":
                        tmpl, vuln = am.group(1).strip(), am.group(2).strip()
                        report.add("HIGH", "RECON", path, lineno,
                                   f"ADCS template '{tmpl}' vulnerable: {vuln}",
                                   hint=f"certipy-ad req -ca <CA> -template '{tmpl}' -upn administrator@<dom> -u <you> -p <pw>")
                        hit = True
                        break
                    if name == "pg_hba auth method":
                        host_typ, db, user, method = am.group(1), am.group(2), am.group(3), am.group(5)
                        if method == "trust":
                            sev = "CRITICAL" if host_typ.startswith("host") else "HIGH"
                            report.add(sev, "ASSIGNED SECRETS", path, lineno,
                                       f"pg_hba TRUST auth: {host_typ} {db} {user}",
                                       hint=f"psql -U {user} -d {db} -h <pg-host>  (NO password required)")
                            hit = True
                            break
                    if name == "redis requirepass":
                        directive, val = am.group(1), am.group(2)
                        if filters.is_placeholder(val):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"redis {directive}: {val}",
                                   hint=f"redis-cli -h <host> -a '{val}' info")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val, source=path, line=lineno))
                        hit = True
                        break
                    if name == "sudoers NOPASSWD":
                        user, cmd = am.group(1), am.group(2).strip()
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"sudoers NOPASSWD  {user}  ->  {cmd[:80]}",
                                   hint=f"as '{user}' run: sudo {cmd.split()[0] if cmd else '<cmd>'}  (check GTFOBins for escape)")
                        hit = True
                        break
                    if name == "cron script ref":
                        # filename gate: only fire on actual cron config files.
                        base = os.path.basename(path).lower()
                        in_cron = ("crontab" in base or "/cron" in path.lower()
                                   or "spool/cron" in path.lower()
                                   or "/etc/anacrontab" in path.lower())
                        if not in_cron:
                            continue
                        script = am.group(1)
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"cron-invoked script: {script}",
                                   hint=f"check writability: ls -la {script}  - if any non-root write -> code-as-root")
                        hit = True
                        break
                    if name == "hashcat potfile":
                        # filename gate: only fire on potfile-shaped paths.
                        # Real hashcat ~/.local/share/hashcat/hashcat.potfile,
                        # custom *.pot/.potfile, or any file containing 'crack'
                        # in the basename.
                        base = os.path.basename(path).lower()
                        if not (base.endswith(('.pot', '.potfile'))
                                or 'potfile' in base or 'hashcat' in base
                                or 'cracked' in base or '.crack' in base):
                            continue
                        h, plain = am.group(1), am.group(2)
                        # plain-half sanity: not just hex (still inside a hash),
                        # not a placeholder, not exactly the same as the hash.
                        if (filters.is_placeholder(plain) or len(plain) < 3
                                or re.match(r'^[a-fA-F0-9]+$', plain)
                                or plain == h):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"hashcat cracked: {h[:40]}... -> '{plain}'",
                                   hint=f"reuse plaintext: nxc smb <host> -u <user> -p '{plain}'  (per the hash's source)")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=plain, source=path, line=lineno))
                        hit = True
                        break
                    if name == "john pot":
                        base = os.path.basename(path).lower()
                        if not (base == 'john.pot' or base.endswith('.pot')
                                or 'john' in base or 'cracked' in base):
                            continue
                        h, plain = am.group(1), am.group(2)
                        if (filters.is_placeholder(plain) or len(plain) < 3
                                or re.match(r'^[a-fA-F0-9]+$', plain)):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"john cracked: {h[:40]}... -> '{plain}'",
                                   hint=f"reuse plaintext: nxc smb <host> -u <user> -p '{plain}'")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=plain, source=path, line=lineno))
                        hit = True
                        break
                    if name == "AWS session token":
                        tok = am.group(1)
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"AWS session token: {tok[:40]}...",
                                   hint="aws sts get-caller-identity  (export AWS_ACCESS_KEY_ID, _SECRET_ACCESS_KEY, _SESSION_TOKEN)")
                        hit = True
                        break
                    if name == "GCP service account":
                        kid = am.group(1)
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"GCP service-account JSON key (kid {kid[:12]}...)",
                                   hint="gcloud auth activate-service-account --key-file <this.json>; gcloud projects list")
                        hit = True
                        break
                    if name == "kubeconfig token":
                        tok = am.group(1)
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"kubeconfig token: {tok[:40]}...",
                                   hint="kubectl --kubeconfig <this> get pods --all-namespaces  -> escalate to nodes via privileged pods")
                        hit = True
                        break
                    if name == "Terraform sensitive":
                        val = am.group(1)
                        if filters.is_placeholder(val):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Terraform 'sensitive' output: {val[:60]}",
                                   hint="reuse value directly - tfstate keeps the plaintext even when marked sensitive")
                        hit = True
                        break
                    if name == "Azure access token":
                        tok = am.group(1)
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Azure access token: {tok[:40]}...",
                                   hint="paste into az or use roadtools/aztoken; check token claims via jwt.io for tenant + roles")
                        hit = True
                        break
                    if name == "supervisord inet creds":
                        u, p = am.group(1), am.group(2)
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"supervisord inet creds: {u}:{p}",
                                   hint=f"curl -u '{u}:{p}' http://<host>:9001/  (web UI + XML-RPC)")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=lineno))
                        hit = True
                        break
                    if name == "asterisk manager":
                        u, p = am.group(1), am.group(2)
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"asterisk manager.conf [{u}]: secret={p}",
                                   hint=f"asterisk AMI: nc <host> 5038; then Action: Login user:{u} secret:{p}")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=lineno))
                        hit = True
                        break
                    if name == "Veeam creds":
                        u, p = am.group(1), am.group(2)
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"Veeam stored cred: {u}:{p}",
                                   hint="Veeam backups carry the destination repo creds; reuse against the SMB/iSCSI target")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=lineno))
                        hit = True
                        break
                    if name == "GH Actions secret ref":
                        sec = am.group(1)
                        report.add("MEDIUM", "RECON", path, lineno,
                                   f"GH Actions secret reference: {sec}",
                                   hint="CI vault secret name - target if you have repo write/PR-comment access")
                        hit = True
                        break
                    if name == "atlassian secret":
                        val = am.group(1)
                        if filters.is_placeholder(val):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"atlassian config <password>: {val}",
                                   hint="reuse against Confluence/Jira admin login; LDAP bind on the same XML often shares the pw")
                        hit = True
                        break
                    if name == "PSCredential SS blob":
                        blob = am.group(1)
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"PSCredential Export-Clixml DPAPI blob ({len(blob)//2}B)",
                                   hint="recoverable ONLY by the same user+host: powershell -c 'Import-Clixml cred.xml | %{ \$_.GetNetworkCredential().Password }'")
                        hit = True
                        break
                    if name == "ovpn auth-user-pass":
                        f_ = am.group(1)
                        report.add("MEDIUM", "INTERESTING FILES", path, lineno,
                                   f"OpenVPN auth-user-pass file ref: {f_}",
                                   hint=f"read {f_} - line 1=user, line 2=plaintext password")
                        hit = True
                        break
                    if name == "WireGuard PrivateKey":
                        key = am.group(1)
                        report.add("HIGH", "PRIVATE KEYS", path, lineno,
                                   f"WireGuard PrivateKey: {key[:24]}...",
                                   hint="copy [Interface] block into wg-quick up <name>.conf and reach internal network")
                        hit = True
                        break
                    if name == "Cisco enable secret":
                        typ, val = am.group(1), am.group(2)
                        if typ == "5":
                            mode, label = "500", "Cisco type-5 (md5crypt)"
                        elif typ == "7":
                            mode, label = "", "Cisco type-7 (reversible XOR)"
                        else:
                            mode, label = "", f"Cisco type-{typ}"
                        sev = "CRITICAL" if typ == "7" else "HIGH"
                        hint = ("offline decrypt via 'ciscot7 -d <val>' (instant - reversible XOR)"
                                if typ == "7" else
                                f"hashcat -m {mode} <hash> rockyou.txt")
                        report.add(sev, "PASSWORD HASHES", path, lineno,
                                   f"{label}: {val[:40]}{'...' if len(val) > 40 else ''}",
                                   hint=hint)
                        hit = True
                        break
                    if name == "token impersonation":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "SeImpersonate / token-impersonation tooling reference",
                                   hint="if running as a service account: PrintSpoofer / GodPotato / JuicyPotato -> SYSTEM")
                        hit = True
                        break
                    # ADO.NET connectionString: parse User ID / Password out cleanly
                    if name == "ADO connectionString":
                        cs = am.group(1)
                        # Iter-7: skip Integrated Security / Trusted_Connection strings
                        # (no password to leak), and skip __VAR__/${VAR}/<TOKEN> templates.
                        cs_low = cs.lower()
                        if ("integrated security" in cs_low
                                or "trusted_connection=yes" in cs_low
                                or "trusted_connection=true" in cs_low):
                            continue
                        pm = re.search(r'(?i)\b(?:password|pwd)\s*=\s*([^;"\'\r\n]{3,})', cs)
                        um = re.search(r'(?i)\b(?:user\s*id|uid|user)\s*=\s*([^;"\'\r\n]{1,60})', cs)
                        if not pm:
                            continue
                        pw = pm.group(1).strip()
                        if (filters.is_placeholder(pw)
                                or pw.startswith('__') and pw.endswith('__')
                                or pw.startswith('${') or pw.startswith('<')):
                            continue
                        u = (um.group(1).strip() if um else "")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"connstring {u + ':' if u else ''}{pw}",
                                   hint=f"DB/service cred: netexec mssql <host> -u '{u or '<user>'}' -p '{pw}' "
                                   "(or mssqlclient.py / reuse on the host)")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=pw,
                                               source=path, line=lineno))
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
    # File-level multi-line passes (after the line-by-line scan completes).
    _multiline_passes(path, report, store)
