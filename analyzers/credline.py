"""credline.py - classify ONE line that may carry a credential.

The single source of truth for "is this line a real cred, and what is it?".
Distinguishes real creds (netexec/cme success, note user:pass, PowerShell
ConvertTo-SecureString, net user add) from the noise that used to flood the
report: pwdump rows, icacls/ACL masks, failed-auth lines, hydra/curl templates,
tool help-strings and source code. Used by keyword/notes/patterns so the logic
lives in ONE place.

classify(line) -> Cred | None
  Cred.kind: 'cred'   real, usable now (high confidence)
             'failed' a cred that FAILED auth (still worth trying elsewhere)
             'pwdump' user<->NT-hash binding (no plaintext; for pass-the-hash)
"""
import re
from analyzers import filters


class Cred:
    __slots__ = ("kind", "user", "password", "nt_hash", "domain", "note")

    def __init__(self, kind, user="", password="", nt_hash="", domain="", note=""):
        self.kind = kind
        self.user = user
        self.password = password
        self.nt_hash = nt_hash
        self.domain = domain
        self.note = note


# ── noise we must NEVER treat as a plaintext cred ──────────────────────────
# icacls / ACL masks:  BUILTIN\Users:(F)   NT AUTHORITY\SYSTEM:(I)(F)   x:(OI)(CI)(F)
_ICACLS = re.compile(
    r':\((?:OI|CI|IO|NP|I|N|F|M|RX|RD|WD|AD|REA|R|W|D|X|DC|S|GR|GW|GE|RC|WO)\)'
    r'|\b(BUILTIN|NT AUTHORITY|CREATOR OWNER|APPLICATION PACKAGE|NT SERVICE|Everyone|Mandatory Label)\b')
# tool help / format strings:  (domain\uid:rid:lmhash:nthash)
_HELPSTR = re.compile(r'(?i)(lmhash|nthash|lm[_ ]?hash|nt[_ ]?hash|uid:rid|rid:lm|'
                      r'<password>|<user(name)?>|domain\\u(id|ser)|dumping .*credentials\s*\()')
# hydra / curl / ffuf templates + brute-force command context
_TEMPLATE = re.compile(r'(?i)(\^USER\^|\^PASS\^|\^USER64\^|FUZZ|§\w|http-post-form|http-get-form|'
                       r'\$\{?USER\}?|\$\{?PASS(WORD)?\}?|<USERNAME>|<PASSWORD>|%USER%|%PASS%|'
                       r'\b(hydra|medusa|ncrack|patator)\b|users?\.txt|pass(words?)?\.txt|rockyou)')
# iter-194: drop the bare `username=\w+&password=` alternative - it FPs on
# real Burp form-urlencoded POST bodies (`username=alice&password=Sunfl0wer!`)
# which are legitimate captures we WANT to classify as creds. The tool-context
# form (`curl -d 'username=X&password=Y' <url>`) is still a template signal,
# so keep it - but also require the presence of a placeholder / brute-list
# marker AFTER the tool token to distinguish `curl -d ...` real POST from
# `hydra -L users.txt -P passwords.txt http-post-form '/login:username=^USER^&password=^PASS^:F=fail'`
_BRUTE_BODY = re.compile(
    r'(?i)\b(curl|wget|hydra|medusa|ncrack|patator|ffuf|wfuzz)\b.*'
    r'(?:(-d|--data)|http-(?:post|get)-form)[^\r\n]{0,200}?'
    r'(?:\^(?:USER|PASS)\^|\$\{?(?:USER|PASS)\}?|FUZZ|<[^>]+>|%[A-Z]+%)'
)
# JSON login body: {"username": "X", "password": "Y"} or ADO.NET-style
# {"Username":"X","Password":"Y"} or {"user":"X","pass":"Y"}. Common in
# Burp captures of AJAX login endpoints and audit logs.
_JSON_LOGIN_BODY = re.compile(
    r'(?i)["\'](?:username|user|login|email|uid)["\']\s*:\s*["\']'
    r'([^"\'\r\n]{1,80})["\']\s*,\s*'
    r'["\'](?:password|pass|pwd|passwd)["\']\s*:\s*["\']'
    r'([^"\'\r\n]{3,80})["\']'
)
# pwdump:  [DOMAIN\]user:RID:LM:NT:::    (NT = group 5, LM = group 4)
_PWDUMP = re.compile(r'(?:([^\s:\\]+)\\)?([^\s:\\]{1,64}):(\d{1,7}):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::')
# netexec / crackmapexec password line:  [+]/[-] domain\user:password [(Pwn3d!)] [STATUS_...]
_NXC_PW = re.compile(r'\[(?P<sign>[+\-])\]\s+(?:(?P<dom>[A-Za-z0-9.\-]+)\\)?(?P<user>[^\s:\\]+):(?P<pw>[^\s]+)')
# netexec pass-the-hash success:  [+] domain\user <space> NThash [(Pwn3d!)]
_NXC_PTH = re.compile(r'\[\+\]\s+(?:(?P<dom>[A-Za-z0-9.\-]+)\\)?(?P<user>[^\s:\\]+)\s+(?P<nt>[a-fA-F0-9]{32})\b')
# STATUS codes: these mean the password was actually CORRECT (account restricted)
_STATUS_VALID = re.compile(r'STATUS_(PASSWORD_EXPIRED|PASSWORD_MUST_CHANGE|ACCOUNT_DISABLED|'
                           r'ACCOUNT_LOCKED_OUT|ACCOUNT_RESTRICTION|LOGON_TYPE_NOT_GRANTED|'
                           r'INVALID_LOGON_HOURS|ACCOUNT_EXPIRED)')
_STATUS_FAIL = re.compile(r'STATUS_(LOGON_FAILURE|NO_SUCH_USER|WRONG_PASSWORD|ACCESS_DENIED|'
                          r'NO_LOGON_SERVERS|TRUSTED_RELATIONSHIP_FAILURE)')
# PowerShell secure string + other inline-pw shapes
_SECSTR = re.compile(r'(?i)ConvertTo-SecureString\s+(?:-(?:String|AsPlainText|Key|Force)\s+)*["\']([^"\']{3,})["\']')
_NETUSER = re.compile(r'(?i)\bnet\s+user\s+(\S+)\s+(\S+)\s+/add')
_UPLABEL = re.compile(r'(?i)\buser(?:name)?\s*[:=]\s*([^\s&="\':]{2,})\b.{0,40}?\bpass(?:word)?\s*[:=]\s*([^\s&="\':]{3,})')
# iter-161: ADO.NET / JDBC / MSSQL connection strings surface constantly
# in .config, appsettings.json, .aspx source, web.config, and Snaffler
# 'connection string' hits. The "User Id"/"UID" and "Password"/"PWD"
# separator words don't survive _UPLABEL's \buser\b anchor because AD
# style is "User Id=sa;Password=xxx" (space between User and Id). Match
# both idioms; support ' or " wrapping. Allow up to 120 chars between
# because full connection strings may squeeze Data Source, Initial
# Catalog, Integrated Security, MultipleActiveResultSets, etc. between
# UID and PWD.
_MSSQL_CS = re.compile(
    r'(?i)(?:\bUser\s*(?:Id|ID)|\bUID)\s*=\s*[\'"]?([^;\'";\s]{2,64})[\'"]?'
    r'\s*;.{0,120}?'
    r'(?:\bPassword|\bPWD)\s*=\s*[\'"]?([^;\'";\s]{3,120})[\'"]?')
_PLAIN = re.compile(r'^(?P<dom>[A-Za-z0-9.\-]+)\\(?P<user>[^\s:\\]{1,64}):(?P<pw>\S{3,})$')
# iter-203: slash-separated cred notes. Common walkthrough shapes:
#   Credentials: alice / Sunfl0wer
#   Login: alice / Sunfl0wer
#   Creds: alice/Sunfl0wer
#   Access: alice / Sunfl0wer!
# Anchor on the intent keyword so we don't FP on `10.10.10.10 / 24` etc.
_SLASH_PAIR = re.compile(
    r'(?i)\b(?:credentials|login|creds?|access|auth|account)\s*[:=]?\s+'
    r'([A-Za-z_][A-Za-z0-9._@\\-]{1,60})\s*/\s*'
    r'([^\s"\',][^\s"\',\r\n]{2,79})'
)
# iter-203: Markdown table row `| user | pass |`. Restrict to rows with
# 2 pipe-separated columns (allow trailing) so `| a | b | c | d |` doesn't
# trigger with the wrong grouping. Also exclude header rows (all-dashes)
# and rows whose first column looks like a numeric ID (INSERT-style tables).
_MD_TABLE_PAIR = re.compile(
    r'^\|\s*([A-Za-z_][A-Za-z0-9._@\\-]{1,40})\s*\|\s*'
    r'([^\s"\'|][^"\'|\r\n]{2,79})\s*\|'
)
# iter-203: Markdown bullet with user:pass shape.
#   - alice: Sunfl0wer
#   * alice:Sunfl0wer
#   + alice: Sunfl0wer!
_MD_BULLET_PAIR = re.compile(
    r'^\s*[-*+]\s+([A-Za-z_][A-Za-z0-9._@\\-]{1,40})\s*:\s*'
    r'([^\s"\'][^"\'\r\n]{2,79})$'
)
# bare note pair:  whole line is exactly  user:pass  (admin:nibbles)
_PAIR = re.compile(r'^([A-Za-z0-9._@$-]{2,40}):([^\s:]{3,40})$')
# creds:/login: <user:pass>  (keyword-prefixed, low FP risk)
_PAIR_KW = re.compile(r'(?i)\b(?:creds?|logins?|credentials?)\s*[:=]\s*'
                      r'([A-Za-z0-9._@$-]{2,40}):([^\s:]{3,40})(?=\s|$)')
# left-hand keys that are prose/markup/config labels, NOT usernames
_NOT_USER = frozenset((
    "note", "notes", "todo", "fixme", "warning", "error", "info", "debug",
    "http", "https", "ftp", "ftps", "file", "url", "uri", "host", "hostname",
    "ip", "ipaddr", "addr", "port", "proto", "date", "time", "datetime",
    "name", "key", "value", "val", "type", "id", "ref", "see", "re", "from",
    "to", "subject", "cc", "bcc", "path", "dir", "folder", "size", "status",
    "code", "line", "col", "row", "version", "ver", "tag", "label", "title",
    "desc", "description", "summary", "example", "eg", "ie", "nmap", "tcp",
    "udp", "open", "closed", "filtered", "service", "os", "cve", "cwe",
    "step", "phase", "task", "goal", "result", "output", "input", "cmd",
    "command", "flag", "hint", "tip", "warn", "fatal", "trace", "level",
    "msg", "message", "data", "json", "xml", "html", "css", "js",
))
# iter-179: `password\s*==(?!>)` excludes ==> arrow separator so
# 'Password ==> RealSecret99' isn't misclassified as code. Same for
# the leading `==\s*['"]?\s*$` alternative.
_CODE = re.compile(r'(?i)(==(?!>)\s*[\'"]?\s*$|\bis\s+None\b|\bis\s+null\b|getenv|os\.environ|'
                   r'\bvar\s+\w|\bdef\s+\w|\bfunction\s|\$\(["\']?#|jquery|document\.|'
                   r'getElementById|Crypt::|->get\(|\.get\(|ConvertFrom|password\s*==(?!>))')
_HASHY = re.compile(r'^[a-fA-F0-9]{16,}$')


def _ok_pw(pw):
    """does this look like a real password value (not placeholder/RID/hash/ACL)?"""
    pw = (pw or "").strip().strip("'\"`")
    if not (3 <= len(pw) <= 60):
        return False
    if pw.isdigit() or _HASHY.match(pw):
        return False
    # iter-7: also reject leading '$' (so '$apr1$...', '$2y$...', etc. don't
    # get mis-classified as plaintext when they're hashes), and embedded ','
    # (which appears in CSV column headers like 'content_md5:thumb_md5,filename,N'
    # but never in real password values).
    if "&" in pw or "=" in pw or "," in pw or pw.startswith(("$(", "$", "^", "<", "%", "-", "/")):
        return False
    if filters.is_placeholder(pw) or filters.is_known_example(pw):
        return False
    if pw.lower() in ("bad", "pass", "password", "test", "admin", "changeme", "none",
                      "user", "convertto-securestring", "null", "true", "false"):
        return False
    return True


# iter-11 corpus mining: ~/.netrc inline cred:
#   machine HOST login USER password PW
#   default login USER password PW
_NETRC = re.compile(
    r'(?i)\b(?:machine\s+(\S+)|default)\s+login\s+(\S+)\s+password\s+([^\s#\r\n]{3,200})')
# iter-11 corpus mining: ~/.pgpass colon-delimited cred row:
#   host:port:db:user:password   ('*' allowed in any of host/port/db/user)
_PGPASS = re.compile(
    r'^(\*|[^:\s#][^:\s]{0,80}):(\*|\d{1,5}):(\*|[^:\s][^:]{0,63}):(\*|[^:\s][^:]{0,63}):'
    r'((?:\\.|[^:\\\r\n]){3,200})\s*$')


# sentence-shaped password hints in notes / LDAP description / HR docs:
#   "password set to X"     (Resolute LDAP description)
#   "my password is X"      (Cicada david.orelious description)
#   "the password is X"     (generic ops notes)
#   "default password is X" / "Your default password is: X"  (HR notices)
#   "gets password X"       (jeffersonian notes shorthand)
# iter-178: "temp password: X" / "temporary password: X" / "initial password: X"
# common OSCP+ note pattern (welcome/onboarding emails, HR resets).
# iter-179: additional walkthrough phrases:
#   "with password X"           login instructions (colon separator)
#   "kerberos password: X"      Kerberos-scoped cred
#   "service/user/admin/root/guest password X"   role-scoped cred
#   "PW: X"                     short-hand notes (pw abbreviation)
#   "Password ==> X"            arrow separator (long-arrow variant)
#   "password set to X"         verb-phrase (no separator needed)
# Order matters: longer separators before shorter ones so ==> doesn't
# get chewed by [:=]+ leaving > behind.
_GETS = re.compile(
    r"(?i)(?:"
    # verb-phrase branches: separator is optional (word-boundary suffices)
    r"\b(?:gets?\s+password|password\s+set\s+to|"
    r"(?:my|the|default|your)\s+(?:default\s+)?password\s+is|"
    r"with\s+password)\b"
    r"\s*(?:[:=]|==>|->)?\s*"
    r"|"
    # anchor-phrase branches: separator required (colon / equal / arrow)
    r"\b(?:(?:temp(?:orary)?|initial|new|reset|welcome|kerberos|service|user|admin|root|guest)"
    r"\s+(?:password|pass)|password|pw)"
    r"\s*(?:==>|->|:=|[:=]+)\s*"
    r")"
    r"[\"']?([^\s\"',;]{3,})")
# English words that *continue* a passive "password is ..." sentence in prose
# (docs/READMEs/security writeups), so the captured token is NOT the secret.
# Only consulted for the colon-less _GETS shape, where the separator is absent.
_GETS_STOP = frozenset((
    "never", "not", "stored", "hashed", "encrypted", "required", "used", "also",
    "only", "set", "case", "sensitive", "same", "different", "correct", "wrong",
    "valid", "invalid", "empty", "blank", "optional", "mandatory", "unique",
    "strong", "weak", "visible", "hidden", "shown", "displayed", "saved", "kept",
    "generated", "created", "changed", "reset", "expired", "disabled", "enabled",
    "important", "secure", "safe", "protected", "transmitted", "sent", "checked",
    # iter-178: policy-doc prose that follows "temp password", "reset password":
    # "temp password requirements are strict", "reset password policy applies"
    "requirements", "requirement", "policy", "policies", "length", "complexity",
    "history", "rules", "rule", "will", "should", "must", "cannot",
    "expires", "expiring", "expiration", "expiry", "aging",
    "prohibits", "prohibited", "allows", "allowed", "supports",
    "enforced", "enforces", "enforcement", "guidelines", "guideline",
    # iter-180: prose adjectives about password quality/state:
    #   "password is guessable" / "password is public" / "password is weak"
    "guessable", "public", "compromised", "leaked",
    "trivial", "simple", "easy", "hardcoded", "predictable", "guess",
    "guessed", "shared", "reused",
))


def classify(line):
    s = line.strip()
    if not s or len(s) > 2000:
        return None

    # ---- hard noise rejects first (order matters) ----
    if _ICACLS.search(s):
        return None
    if _HELPSTR.search(s) and "[+]" not in s and "[-]" not in s:
        return None

    # iter-11: .netrc inline (machine HOST login USER password PW)
    m = _NETRC.search(s)
    if m and _ok_pw(m.group(3)):
        return Cred("cred", user=m.group(2),
                    password=m.group(3).strip("'\""),
                    note=f"netrc machine {m.group(1) or 'default'}")

    # iter-11: .pgpass colon-delimited (host:port:db:user:password)
    m = _PGPASS.match(s)
    if m and _ok_pw(m.group(5)):
        host, _, _, user, pw = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        return Cred("cred", user=user, password=pw.replace("\\:", ":"),
                    note=f"pgpass host={host}")

    # ---- PowerShell ConvertTo-SecureString (real plaintext in quotes) ----
    m = _SECSTR.search(s)
    if m and _ok_pw(m.group(1)):
        return Cred("cred", password=m.group(1).strip("'\"`"), note="PowerShell SecureString")

    # ---- net user add ----
    m = _NETUSER.search(s)
    if m and _ok_pw(m.group(2)):
        return Cred("cred", user=m.group(1), password=m.group(2), note="net user add")

    # ---- netexec / cme pass-the-hash success (user <space> NT) ----
    m = _NXC_PTH.search(s)
    if m and not filters.is_blank_hash(m.group("nt")):
        return Cred("pwdump", user=m.group("user"), nt_hash=m.group("nt").lower(),
                    domain=m.group("dom") or "", note="netexec PtH (Pwn3d!)" if "Pwn3d" in s else "netexec PtH")

    # ---- netexec / cme password result line ----
    m = _NXC_PW.search(s)
    if m:
        pw = m.group("pw")
        if _HASHY.match(pw) or pw.isdigit():
            return None
        valid_restricted = bool(_STATUS_VALID.search(s))
        failed = (m.group("sign") == "-" or _STATUS_FAIL.search(s)) and not valid_restricted
        if _ok_pw(pw):
            note = ("netexec valid (account restricted)" if valid_restricted else
                    "netexec FAILED auth" if failed else "netexec valid")
            return Cred("failed" if failed else "cred", user=m.group("user"),
                        password=pw, domain=m.group("dom") or "", note=note)
        return None

    # ---- pwdump row -> user<->NT binding (no plaintext) ----
    m = _PWDUMP.search(s)
    if m and not _ICACLS.search(s):
        nt = m.group(5).lower()
        if filters.is_blank_hash(nt):
            return None
        # iter-123: impacket-secretsdump -history emits pwdump rows for
        # previous passwords with usernames like 'svc_backup_history0' /
        # 'svc_backup_history1'. Strip the suffix so the hash binds to
        # the actual account (svc_backup) - operator can PtH with this
        # against the real user; a matching entry in DPAPI blobs or
        # cached service creds might still accept the old hash.
        _user = m.group(2)
        _user_stripped = re.sub(r'_history\d+$', '', _user, flags=re.IGNORECASE)
        return Cred("pwdump", user=_user_stripped, nt_hash=nt, domain=m.group(1) or "")

    # ---- templates / brute bodies / code reject ----
    if _TEMPLATE.search(s) or _BRUTE_BODY.search(s) or _CODE.search(s):
        return None

    # ---- explicit Username:/Password: on one line ----
    m = _UPLABEL.search(s)
    if m and _ok_pw(m.group(2)):
        return Cred("cred", user=m.group(1), password=m.group(2), note="user/pass label")

    # ---- ADO.NET / MSSQL connection string: User Id=X;...;Password=Y ----
    # iter-161: matches web.config / appsettings.json / .aspx source lines
    # that _UPLABEL missed because "User Id" (with space) doesn't fit
    # \buser(?:name)?\s*[:=].
    m = _MSSQL_CS.search(s)
    if m and _ok_pw(m.group(2)):
        return Cred("cred", user=m.group(1), password=m.group(2),
                    note="MSSQL/ADO.NET connection string")

    # iter-194: JSON login body from Burp captures / audit logs.
    # {"username":"alice","password":"P@ss"} shape - user + pw quoted +
    # comma-separated. Also matches the "user"/"pass" short aliases.
    m = _JSON_LOGIN_BODY.search(s)
    if m and _ok_pw(m.group(2)):
        return Cred("cred", user=m.group(1), password=m.group(2),
                    note="JSON login body")

    # ---- plain domain\user:password note line ----
    m = _PLAIN.match(s)
    if m and _ok_pw(m.group("pw")) and "\\" not in m.group("pw"):
        return Cred("cred", user=m.group("user"), password=m.group("pw"),
                    domain=m.group("dom"), note="note cred")

    # ---- creds:/login: user:pass  (keyword-prefixed) ----
    m = _PAIR_KW.search(s)
    if m and _ok_pw(m.group(2)) and m.group(1).lower() not in _NOT_USER:
        return Cred("cred", user=m.group(1), password=m.group(2), note="note cred")

    # ---- bare note pair: line is exactly user:pass (admin:nibbles) ----
    m = _PAIR.match(s)
    if (m and _ok_pw(m.group(2)) and m.group(1).lower() not in _NOT_USER
            and any(ch.isalpha() for ch in m.group(1))):
        return Cred("cred", user=m.group(1), password=m.group(2), note="note cred")

    # iter-203: slash-separated cred note (`Credentials: alice / Sunfl0wer`).
    # Keyword-anchored so `10.10.10.10 / 24` (CIDR notation) doesn't fire.
    m = _SLASH_PAIR.search(s)
    if (m and _ok_pw(m.group(2))
            and m.group(1).lower() not in _NOT_USER):
        return Cred("cred", user=m.group(1), password=m.group(2),
                    note="slash-separated note")

    # iter-203: Markdown bullet with `- alice: Sunfl0wer`. Bullet-anchored
    # so we don't clash with the bare-user:pass rule above (which needs
    # the entire line to be user:pass).
    m = _MD_BULLET_PAIR.match(s)
    if (m and _ok_pw(m.group(2))
            and m.group(1).lower() not in _NOT_USER):
        return Cred("cred", user=m.group(1), password=m.group(2),
                    note="markdown bullet")

    # iter-203: Markdown table row `| alice | Sunfl0wer |`. Also captures
    # 3+ column tables (username/password/role); we take the first two
    # non-header columns. Header-row check: reject if any of the captured
    # values look like a column-header word.
    m = _MD_TABLE_PAIR.match(s)
    if m:
        u, p = m.group(1).strip(), m.group(2).strip()
        _hdr_words = {"user", "username", "password", "pass", "pw",
                      "login", "name", "notes", "role", "email"}
        if (u.lower() not in _hdr_words and p.lower() not in _hdr_words
                and u.lower() not in _NOT_USER
                and _ok_pw(p)
                and not re.fullmatch(r'-+', u)  # skip separator row
                and not re.fullmatch(r'-+', p)):
            return Cred("cred", user=u, password=p, note="markdown table")

    # ---- note shorthand: "GETS PASSWORD: x" / "the password is x" ----
    # iter-180: strip trailing sentence punctuation (.?) for the stopword
    # check so prose tokens like "guessable." (with the sentence period)
    # don't slip past the stopword set. Preserve the raw token in the
    # returned value - `!` is a valid password char so we can't rstrip it,
    # and legit trailing `.` inside a password is extremely rare vs the
    # prose-period FP savings.
    m = _GETS.search(s)
    if m:
        _raw = m.group(1).strip("'\"`")
        _tok_check = _raw.rstrip(".?").lower()
        if _ok_pw(_raw) and _tok_check not in _GETS_STOP:
            # iter-189: try to pull the user from PostgreSQL/MySQL DDL context
            # (CREATE|ALTER USER X WITH PASSWORD 'Y' | IDENTIFIED BY 'Y'). The
            # `note password` fallback loses the user otherwise.
            _user_m = re.search(
                r'(?i)(?:CREATE|ALTER)\s+USER\s+["\'`]?'
                r'([A-Za-z_][A-Za-z0-9_.-]{1,63})["\'`]?', s)
            _u = _user_m.group(1) if _user_m else ""
            return Cred("cred", user=_u,
                        password=_raw.rstrip(".?"), note="note password")

    return None


def looks_like_noise(line):
    """True if the line is clearly NOT a literal credential assignment - a
    template/brute command, ACL mask, help-string or source code. Used by the
    generic keyword=value pass to avoid flagging `password=^PASS^` / `curl
    ...password=bad` / `if password == ''`."""
    return bool(_TEMPLATE.search(line) or _BRUTE_BODY.search(line)
                or _ICACLS.search(line) or _CODE.search(line)
                or (_HELPSTR.search(line) and "[+]" not in line and "[-]" not in line))


def is_pwdump_row(line):
    """cheap check used by patterns.py to bind user<->NT and skip generic match."""
    m = _PWDUMP.search(line)
    if not m:
        return None
    nt = m.group(5).lower()
    if filters.is_blank_hash(nt):
        return None
    # iter-123: strip -history suffix (see classify() pwdump branch).
    _user = re.sub(r'_history\d+$', '', m.group(2), flags=re.IGNORECASE)
    return (_user, nt, m.group(1) or "")     # (user, nt_hash, domain)
