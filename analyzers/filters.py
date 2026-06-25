"""filters.py - shared false-positive reduction for every analyzer.

Ported from the published heuristics of detect-secrets (Yelp), gitleaks,
trufflehog and ripsecrets. All FP logic lives HERE so the analyzers stay
small and consistent. Each predicate returns True when a value should be
SUPPRESSED (i.e. it is noise, not a real secret).

The single biggest real-world FP source we have measured (a full HTB loot
tree produced 1662 bogus "high entropy" hits) is base64-encoded binary blobs
from LDAP dumps - objectGUID / objectSid are 16-byte values that base64 into
22-char `...==` tokens. `is_base64_binary()` plus `is_ldap_noise()` kill those.
"""
import re
import math
import base64
import binascii
import string

# ── 1. placeholder / template / env-var-reference values ───────────────────
# (gitleaks global allowlist regexes + detect-secrets is_templated_secret)
_PLACEHOLDER_RE = [re.compile(p) for p in [
    r'(?i)^(true|false|null|none|nil|undefined|n/?a|tbd|todo|fixme|empty)$',
    r'^(.)\1{2,}$',                                   # repeated single char: aaaa **** ....
    r'^\$(?:\d+|\{\d+\})$',                           # $1  ${1}
    r'^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$',             # $VAR  ${VAR}
    r'^\{\{[^}]{1,60}\}\}$',                          # {{ template }}
    r'^\$\{\{[^}]{1,80}\}\}$',                        # ${{ secrets.X }}  (GH Actions)
    r'^%[A-Za-z_][A-Za-z0-9_]*%$',                    # %VAR%  (Windows)
    r'^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$',            # printf %s %d
    r'^\{\d{0,2}\}$',                                 # {0} {12}
    r'^@[A-Za-z_]+@$',                                # @VAR@  (autotools)
    r'^<[^>]{1,40}>$',                                # <your-key-here>
    r'^\[[^\]]{1,40}\]$',                             # [REDACTED]
]]

# dummy/sample values (gitleaks stopwords + ripsecrets + common practice)
_PLACEHOLDER_WORDS = {
    "changeme", "change-me", "change_me", "password", "passwd", "pass", "secret",
    "mysecret", "secretkey", "apikey", "api_key", "yourapikey", "token", "mytoken",
    "example", "test", "testing", "sample", "demo", "dummy", "fake", "mock",
    "placeholder", "todo", "fixme", "none", "null", "nil", "undefined", "default",
    "admin", "root", "user", "username", "guest", "foo", "bar", "baz", "qux",
    "foobar", "your_password", "your-password", "yourpassword", "your_api_key",
    "your-api-key", "your_secret", "your_token", "insert_here", "insert_key_here",
    "replace_me", "redacted", "notarealkey", "donotuse", "tbd", "xxx", "xxxx",
    "xxxxx", "xxxxxxxx", "password1", "qwerty", "abc123", "letmein", "secret123",
    "hunter2", "topsecret", "supersecret", "enter_password_here", "string",
    "anonymous", "value", "somevalue", "pwd", "credentials",
}

# canonical documentation / example secrets (gitleaks EXAMPLE allowlist)
_KNOWN_EXAMPLES = {
    "akiaiosfodnn7example",
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
    "00000000-0000-0000-0000-000000000000",
    "examplekey", "aidaexample",
}
_EXAMPLE_SUFFIX = re.compile(r'(?i)example$')

_ANGLE = re.compile(r'^<.*>$|^\[.*\]$')
_UUID = re.compile(r'(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')


def is_placeholder(value):
    """value is a template / env-ref / dummy / redaction string."""
    if not value:
        return True
    v = value.strip().strip('"\'`')
    if not v:
        return True
    low = v.lower()
    if low in _PLACEHOLDER_WORDS:
        return True
    if _ANGLE.match(v):
        return True
    if len(set(v)) == 1 and v[0] in "*xX-._#0=":      # ****  xxxx  ----  ====
        return True
    for rx in _PLACEHOLDER_RE:
        if rx.match(v):
            return True
    return False


def is_known_example(value):
    v = value.strip().strip('"\'`').lower()
    if v in _KNOWN_EXAMPLES:
        return True
    if _EXAMPLE_SUFFIX.search(v):
        return True
    return False


def is_uuid(value):
    return bool(_UUID.match(value.strip().strip('"\'`')))


# ── 2. code constructs misread as secrets ──────────────────────────────────
# value side is a function call / subscript / attribute, not a literal.
_INDIRECT = re.compile(r'[\w.\-]+\s*[\[\(][^\v]*[\]\)]\s*$')
_CODE_VALUE = re.compile(
    r'(?i)^(none|null|nil|true|false|undefined|self\.\w+|this\.\w+|cls\.\w+|'
    r'os\.environ.*|process\.env\.\w+|getenv.*|getpass.*|input\(.*|prompt.*|'
    r'request\..*|config\..*|conf\[.*|args\..*|options\.\w+|environ\[.*)')
_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$')


def is_code_not_literal(value, line=""):
    """True when the value looks like code (a reference/call) rather than a
    literal secret. `line` is the full source line for context."""
    v = value.strip().strip('"\'`')
    if not v:
        return True
    if _CODE_VALUE.match(v):
        return True
    if _INDIRECT.search(v):                            # foo.get(x)  env['X']
        return True
    # bare dotted identifier that is NOT quoted in the source -> a variable ref
    if _IDENTIFIER.match(v) and f'"{v}"' not in line and f"'{v}'" not in line:
        return True
    return False


# ── 3. sequential / repeated strings & keyboard walks ──────────────────────
_SEQS = (
    string.ascii_uppercase * 2 + string.digits + "+/",
    string.digits + string.ascii_uppercase * 2 + "+/",
    (string.digits + string.ascii_uppercase) * 2,
    string.digits * 2,
    string.hexdigits.upper() * 2,
    string.ascii_lowercase * 2,
)
_WALKS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "qwerty", "qazwsx",
          "1qaz2wsx", "1q2w3e4r", "qwertz", "azerty")


def is_sequential(value):
    """abcdef / 123456 / STUVWXYZ / keyboard walk (detect-secrets is_sequential_string)."""
    v = value.strip().strip('"\'`')
    if len(v) < 4:
        return False
    up = v.upper()
    if any(up in seq for seq in _SEQS):
        return True
    low = v.lower()
    if any(low in w or w in low for w in _WALKS):
        return True
    # monotonic run of code points: abcd / 1234 / dcba
    diffs = {ord(b) - ord(a) for a, b in zip(low, low[1:])}
    if diffs and (diffs <= {1} or diffs <= {-1}):
        return True
    return False


# ── 4. entropy + character-class heuristics ────────────────────────────────
def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def char_classes(s):
    n = 0
    if any(c.islower() for c in s):
        n += 1
    if any(c.isupper() for c in s):
        n += 1
    if any(c.isdigit() for c in s):
        n += 1
    if any(not c.isalnum() for c in s):
        n += 1
    return n


def has_digit(s):
    return any(c.isdigit() for c in s)


# ── 5. base64 binary blobs (GUID / SID / cert bytes) - the #1 FP source ─────
_TEXTCHARS = set(range(32, 127)) | {9, 10, 13}


def _b64_decode(tok):
    if len(tok) % 4 != 0 or len(tok) < 8:
        return None
    try:
        return base64.b64decode(tok, validate=True)
    except (binascii.Error, ValueError):
        return None


def decodes_to_text(tok):
    """base64 token decodes to a printable ASCII string (a possible encoded
    secret we DO want to surface)."""
    raw = _b64_decode(tok)
    if raw is None:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if s and all((ord(c) in _TEXTCHARS) for c in s):
        return s.strip()
    return None


def is_base64_binary(tok):
    """base64 token that decodes to a SHORT binary blob - objectGUID (16B),
    objectSid (12-28B), thumbprints, key bytes. These flood entropy scans from
    LDAP/AD dumps and are never themselves the secret string."""
    raw = _b64_decode(tok)
    if raw is None:
        return False
    if decodes_to_text(tok) is not None:
        return False                                   # printable -> keep
    # non-printable bytes -> binary. Short ones are IDs/handles; flag them.
    if len(raw) <= 32:
        return True
    nontext = sum(1 for b in raw if b not in _TEXTCHARS)
    return (nontext / len(raw)) > 0.30                 # mostly-binary blob


# ── 6. LDAP / AD dump noise ────────────────────────────────────────────────
_LDAP_DN = re.compile(r'(?i)^(CN|OU|DC|DN)=')
_LDAP_ATTR = re.compile(
    r'(?i)^\s*(objectGUID|objectSid|objectGUID::|objectSid::|msExch|'
    r'distinguishedName|whenCreated|whenChanged|uSNCreated|uSNChanged|'
    r'pwdLastSet|lastLogon|badPasswordTime|accountExpires|cn|ou|dn)\s*:')


def is_ldap_noise(tok, line=""):
    """LDAP distinguished-name fragment, GUID, or an ldapsearch attribute line
    whose value is a binary/GUID blob."""
    t = tok.strip()
    if _LDAP_DN.match(t):
        return True
    if _UUID.match(t):
        return True
    if line and _LDAP_ATTR.match(line):
        return True
    return False


# ── 7. structural skips (urls / paths / data uris / git shas) ──────────────
_URL = re.compile(r'(?i)^[a-z][a-z0-9+.\-]*://')
_PATH = re.compile(r'^(?:/|\./|\.\./|[A-Za-z]:\\|\\\\)')
_DATAURI = re.compile(r'(?i)data:[\w/.+\-]+;base64,')


def is_structural_noise(tok, line=""):
    if _URL.match(tok) or _PATH.match(tok):
        return True
    if line and _DATAURI.search(line):
        return True
    return False


# ── 8. the entropy gate used by the entropy analyzer ───────────────────────
def entropy_is_interesting(tok, line="", threshold=4.0, min_len=16, max_len=120):
    """Combined gate: returns True only for tokens that look like a REAL
    unlabeled secret. Order = cheapest filters first."""
    n = len(tok)
    if not (min_len <= n <= max_len):
        return False
    if is_structural_noise(tok, line):
        return False
    if is_ldap_noise(tok, line):
        return False
    if is_base64_binary(tok):
        return False
    if is_placeholder(tok) or is_known_example(tok) or is_uuid(tok):
        return False
    if is_sequential(tok):
        return False
    if not has_digit(tok):                             # trufflehog KeyIsRandom
        return False
    if char_classes(tok) < 2:                          # single-case word/hex/path
        return False
    return shannon_entropy(tok) >= threshold


# ── 9. blank / default AD hash constants (recognise, never crack) ──────────
BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"          # empty LM half
BLANK_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"          # empty-password NT hash
# Microsoft's PUBLISHED GPP AES key (so cpassword is always decryptable)
GPP_AES_KEY = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"

_BLANK_HASHES = {BLANK_LM, BLANK_NT}


def blank_hash_note(h):
    """return a human note if `h` is a known blank/empty AD hash, else None."""
    hl = h.lower()
    if hl == BLANK_LM:
        return "EMPTY LM hash (LM disabled) - ignore, not crackable"
    if hl == BLANK_NT:
        return "EMPTY password (blank NT hash) - account has NO password; try blank auth"
    return None


def is_blank_hash(h):
    return h.lower() in _BLANK_HASHES


# ── 10. directories / files to skip entirely ───────────────────────────────
# payload & wordlist trees produce thousands of fake creds (e.g. SecLists,
# xxe-injection-payload-list). Skip them wholesale.
SKIP_DIR_NAMES = {
    "site-packages", "node_modules", "vendor", "__pycache__", ".git",
    "dist-info", "templates", "languages", "locale", "bower_components",
    ".svn", ".hg", ".idea", ".vscode", "test-data", "testdata",
}
_SKIP_DIR_RE = re.compile(
    r'(?i)(seclists|payloadsalltthethings|payloads?-?all|fuzzdb|'
    r'wordlists?|payload-?list|payload-?generator|xxe-?injection|'
    r'dirb/wordlists|rockyou)')


def should_skip_dir(name, full_path=""):
    if name in SKIP_DIR_NAMES:
        return True
    if _SKIP_DIR_RE.search(name):
        return True
    return False


# unzipped Office / OpenXML internals + scan-tool XML that are never creds
_NOISE_FILE_RE = re.compile(
    r'(?i)('
    r'/(_rels|docProps|word|xl|ppt|customXml)/|'        # unzipped .docx/.xlsx/.pptx
    r'\[Content_Types\]\.xml$|'
    r'\.min\.(js|css)$|\.map$|'
    r'(^|/)(package-lock\.json|yarn\.lock|composer\.lock|Gemfile\.lock|'
    r'poetry\.lock|Cargo\.lock|go\.sum|pnpm-lock\.yaml)$'
    r')')
_NMAP_XML = re.compile(r'(?i)(nmap|masscan|allports|alltcp|-tcp|-udp|sslscan)')


def is_noise_file(path, name=""):
    name = name or path.rsplit("/", 1)[-1]
    if _NOISE_FILE_RE.search(path):
        return True
    if name.lower().endswith(".xml") and _NMAP_XML.search(name):
        return True
    return False


def is_secrethound_output(path):
    """Detect our own JSON export so a re-scan doesn't ingest its own findings.
    Cheap structural sniff of the first ~2KB."""
    if not path.lower().endswith(".json"):
        return False
    try:
        with open(path, "r", errors="ignore") as fh:
            head = fh.read(2048)
    except OSError:
        return False
    return ('"severity"' in head and '"category"' in head and
            ('"detail"' in head or '"hint"' in head))
