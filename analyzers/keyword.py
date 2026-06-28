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
    ("SUID GTFOBins", re.compile(
        r'(?im)^[-l]rws[\s\S]{0,40}\b(/(?:usr/)?(?:s?bin)/'
        r'(?:python\d*|perl|ruby|php|nmap|find|vim|less|more|nano|tee|'
        r'awk|cp|mv|cat|tar|zip|gzip|env|node|wall|dd|expect|rsync|'
        r'gdb|gimp|lua|mawk|nice|nohup|pkexec|setarch|socat|strace|'
        r'taskset|tclsh|unzip|wget|curl|xargs|xxd|zsh))$')),
    # `getcap -r /` output - capability bits on binaries.
    # `/usr/bin/python3 = cap_setuid+ep`
    # iter-11 FP audit: LHS must be an absolute path (rejects Makefile
    # `MY_VAR = cap_setuid_helper`); RHS cap must be properly suffixed.
    ("Linux capability", re.compile(
        r'^(/\S+)\s+=\s+(cap_(?:setuid|setgid|net_raw|dac_read_search|chown|'
        r'fowner|kill|net_bind_service|sys_admin|sys_ptrace|net_admin|'
        r'sys_module|sys_chroot|sys_time|audit_control)(?:[,+][\w+]+)?)(?:\s|,|$)',
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
    for m in _PV_KERB.finditer(text):
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
                    report.add(sev, "CRED PAIRS", path, lineno, label,
                               f"netexec smb <DC-IP> -u '{who}' -p '{c.password}' -k")
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
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"PowerShell PSCredential: {u}:{p}",
                                   hint=f"reuse: netexec smb <DC-IP> -u '{u}' -p '{p}'")
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
                    if name == "GPP cpassword inline":
                        blob = am.group(1)
                        if filters.is_placeholder(blob) or filters.is_canonical_sample(blob):
                            continue
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
