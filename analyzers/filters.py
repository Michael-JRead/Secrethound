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
import hashlib
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
    # iter-11: JDK/JKS/Tomcat/Atlassian canonical defaults that fill docs +
    # writeups (Maven settings.xml, Confluence install guides, Java truststore).
    "changeit", "changeit123", "tomcat", "manager", "jonas", "redhat", "kafka",
    # development/test/local placeholder credentials caught by the URL-with-creds
    # and CRED PAIRS rules in iter-7 (docker-compose dev fixtures, .env.dev,
    # *.fixture.json - 'devuser:devpass', 'appuser:apppass', 'minio_admin', etc.).
    "devuser", "devpass", "dev_user", "dev_pass", "developer", "developerpass",
    "dbuser", "dbpass", "db_user", "db_pass", "appuser", "apppass",
    "app_user", "app_pass", "testuser", "testpass", "test_user", "test_pass",
    "localuser", "localpass", "local_dev", "localdev", "localdevpass",
    "l0caldevpass", "demo_app", "demoapp", "demo_user", "demo_pass",
    "minio_admin", "minio_pass", "minioadmin", "miniopass",
    "rabbituser", "rabbitpass", "guestpass", "rabbitmq",
    # FP-audit additions: hyphenated/instructive placeholders found in wp-config
    # samples, docker-compose templates, .env.example files (iter 7).
    "must-be-changed-on-first-login", "put-your-strong-password-here",
    "put_your_password_here", "change_this_password", "change-this-password",
    "change_me_before_deploy", "change-me-before-deploy",
    "your-strong-password", "your_strong_password", "your-secret-key", "your_secret_key",
    "your-jwt-secret", "your_jwt_secret", "your-app-secret", "your_app_secret",
    "insert-your-password-here", "your-password-here", "your_password_here",
    "to-be-set", "to_be_set", "fill-me-in", "fill_me_in", "secret-here", "secret_here",
}

# substrings that, anywhere in the value, mark it as a clear placeholder/template
# (e.g. 'put your unique phrase here', 'CHANGE_ME', 'your-secret-key-here').
_PLACEHOLDER_SUBSTR = re.compile(
    r"(?i)(?:put[\s_-]your[\s_-]\w+[\s_-]here|change[\s_-]?me|change[\s_-]this[\s_-]?\w*|"
    r"insert[\s_-]\w+[\s_-]here|your[\s_-]unique[\s_-]phrase[\s_-]here|"
    r"unique[\s_-]phrase[\s_-]here|your[\s_-]\w+[\s_-]here|"
    r"replace[\s_-]\w+[\s_-]here|to[\s_-]be[\s_-]set|"
    r"<[\w\s_-]{3,40}>|__[A-Z][A-Z0-9_]+__)"
)
# iter-9: embedded CamelCase placeholder words. A safe gate against doc-sample
# strings like 'MyCpasswordExampleHere==' or 'YourTokenHere' - matches only
# when a placeholder-marker word ('Example', 'Sample', 'Demo', 'Placeholder',
# 'YourKey', 'NotARealKey', 'RedactedFor', 'TruncatedFor') is paired with a
# secret-noun word ('Here', 'Password', 'Cpassword', 'Token', 'Key', 'Secret',
# 'Cred', 'Hash', 'Value', 'Pwd'). Won't FP on legit passwords because real
# passwords don't pair these specific tokens.
_PLACEHOLDER_EMBEDDED = re.compile(
    r"(?:(?:Example|Sample|Demo|Placeholder|YourKey|YourToken|YourSecret|"
    r"NotARealKey|RedactedFor|TruncatedFor)"
    r"(?:Here|Cpassword|Password|Pwd|Token|Key|Secret|Cred|Hash|Value|PSK|"
    r"Authkey|API|Auth))"
    # iter-20: also catch the SAMPLE-X / EXAMPLE-X dash variant
    r"|(?:(?:SAMPLE|EXAMPLE|PLACEHOLDER|YOUR)-[A-Z]{2,12})"
)

# canonical documentation / example secrets (gitleaks EXAMPLE allowlist + the
# upstream-published doc samples our FP-audit caught in the wild).
# Stored as SHA-256 digests so the repository itself never contains the literal
# token values (avoids tripping GitHub Push Protection / secret scanners on
# our OWN copy of legitimately-published vendor doc examples). Each entry
# corresponds to a single vendor-published doc / cheatsheet sample; we hash
# the lowercased value on lookup.
_KNOWN_EXAMPLE_HASHES = {
    # gitleaks AWS allowlist (akiaiosfodnn7example):
    "2eb6c6020c2290c8d9020b570bd9d6ef7577109b2d51c2510b61674ca782ee18",
    # AWS secret-key canonical example:
    "9b4d1fe07ab0b901c8c549a3431f4cd95ffb0149cbbbd41a37026098e0a857c0",
    # all-zero UUID:
    "12b9377cbe7e5c94e8a70d9d23929523d14afa954793130f8a3959c7b849aca8",
    "337c877f20d86d7a499fa090e82c7e3fd1aaf9eb819d68b6f2236de3a84881cb",
    "347791c2e0576c58e2778b5bdd3123c883aa0c9e168f25f2d3e571563e38fb54",
    # Stripe published docs example key (literally in their API docs):
    "70775e630d40625a16439c6f582921f68e12be686ca6f5026a9357f3729da2cc",
    # Mailgun published API-key example from their docs:
    "9c846fdf0fa8955c377d0301542ee20ecd4585c5f359aa0a4cf15d44424f573d",
    # bcrypt + PHC publicly-published canonical example hashes (wikis,
    # man-pages, blog posts; never live loot):
    "21f1f636b5101540971e1fcbea6b110e52a740cec109acc1df9cc519586a7d99",
    "090ffa9581230bcd99110d11e4e9af0cc6785206e183abec79c347db2f2db42b",
    "0c381dbe3503d09f7c7ef582a924a2e0f69d4c01da23590616ff4288f3a65c7d",
    "d4fc0b085b67411e02addb86df8839f14610f7f6c1e2594e245a01df90b03edd",
    # well-known sha1("") empty-string hash:
    "07e23ede2756aa3f5f7cc9759117c4910875e032c27b8556a1e20626224f10ec",
    # md5("") / md5("password") / md5("hello world") / hashcat example_hashes:
    "f215faf9d88b7f0a881632ee22459ee452a296c808d261b6cc993d3a1fd0600e",
    "3f2cd8e57b096fe7e4a78a5627e34ca3f885ad65a56e61c287cf4211bbc5949f",
    "5885ad7bdb33da94583387b197bbef4a055f53ac34c85b5e00794945d6180074",
    "955e6b0e5c578b1709ef87fbba45eea5d2cf6de022a11e9e56fe73a4e89dbf99",
    # iter-8 round-1: md5("0").."md5("9") used as canonical sample values in
    # tutorial/test/manifest content (the FP audit caught md5("2") =
    # c81e728d... and md5("hello world") = 5eb63bbb... and dozens more).
    "db2d8e82412b775f358732deba189805318d3bb40008c333171f078dcd4be0b8",
    "08428467285068b426356b9b0d0ae1e80378d9137d5e559e5f8377dbd6dde29f",
    "c28e1316f6231ba322f55e6d4456669f1cd3685b9bc0e7fdfbdd4b4ef110462a",
    "e89f38039ee41ccb137879a1d1f237f5f3679ab0dea961e78d77d48becfc7766",
    "a200779402d76af34f32c421c11eca575d769559db4589868b19cf2e7d37d936",
    "ee8d495a7c56b7b413bbf86373a5d9da1f7e8aeb514a4c608e8fff1d43b17fa7",
    "249654783a9846267c86af2c19d7962d88bd02859a4b3fe32fd023a2f25b77a6",
    "403dd45c5e49532f648e756d9178b73467a741444a321d2e0755ebde19ac8523",
    "6f3a8dc0c44c0c8717e9b24bdea782439b701318f4403b9c9ee331a29220dbca",
    "7c71f44974a08cb005a0d5e8f03dc58c82395646b7a265743df9104a8e8a2bd1",
    # md5("a"-"d"), md5("admin"/"user"/"test"/"root"/"foo"/"bar")
    "418dd73df63bfe1dc9b1d126d340ccf4941198ccf573eff190a6ff8dc69e87e4",
    "2c0a4e0b13245967f73430247edce6de977a0b94e2ca2b0c29ceac2ab14e600f",
    "8570cd56d526f492320d3f61ec76e6dad426f17be01be6677314dfd5f9c21d91",
    "9da114d1ac5ba27ac496b2a312e3788f6ca8be15867233c3469398fdc037634e",
    "465c194afb65670f38322df087f0a9bb225cc257e43eb4ac5a0c98ef5b3173ac",
    "fb5451a6ac9587186a2e3e53d9fce7152cdf2f02ff8bb7155ba6e78388b1d2a3",
    "52bbea75ee75a6f1d24781d56e6c8ffb9b76e1024013b516bbaaac27e21ae9e0",
    "ee258b5e3a3e3b7811f16a520ab2c1635f430a8c484df9dfe81fb42ad83d40c2",
    "efa4ee6985aba79352b4b9acd06e40da46e38b0c8a44cece339e2430266567a3",
    "879adf17f74556c341ab4f275929b4b9384ca519092b26454f12cad665ab70cf",
    # md5("123"/"123456"/"password"/"p@ssw0rd"/"hello"/"world"/"hello world")
    "65829e542dd151f443cc997270c61e78c042a82d687cc13844bf2c1813714600",
    "cdf4a007e2b02a0c49fc9b7ccfbb8a10c644f635e1765dcf2a7ab794ddc7edac",
    "3b1aab613bb2badfe7d436ec60be2c6a75904ccfee613ab374bfedc938c62f5d",
    "4914e23374bb211e3dca0df7636fefffc7fedd94f1340ae81c7d6c07b7113e9b",
    "e994bc29fe082eebabcd2c92195b208338fee353b1d677279515eaa9b7963beb",
    # sha1 of empty / 'password' / 'admin' + MySQL canonical sha1(sha1())
    "0d287772dfced30917b9dbb547a3dfc2b8ddfa82ef867191f73c64f4770face9",
    "b5a04226bda8fc65a475e3e76359fdec6fe75dced1924004d1e170cc47ea3f1b",
    "bc3ec9c5285345d216ee1a9fa8fd679f90b97bfe3b5ecb2f095dcd93fd12932b",
    "2b2413c0ca3d295c739e0eaacc417ee7786a2d6768ee53ab55f4fa60c15142ac",
}


def _is_known_doc_example(value_lc):
    """SHA-256 lookup against the canonical-example list (stored as digests
    so the repo never contains the literal vendor doc tokens)."""
    return hashlib.sha256(value_lc.encode()).hexdigest() in _KNOWN_EXAMPLE_HASHES
_EXAMPLE_SUFFIX = re.compile(r'(?i)example$')

# Case-sensitive substring matches for canonical doc examples. JWTs encode
# their payload in base64url which IS case-sensitive, and the JWT.io 'John Doe'
# example payload (`eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIg`) is
# the most-copy-pasted JWT in the world. Same idea for the canonical 'Hello,
# World!' base64 in tutorials.
_KNOWN_EXAMPLE_SUBSTR = (
    # JWT.io 'John Doe' canonical payload (base64url of {"sub":"1234567890","name":"John Doe","iat":1516239022})
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
    # JWT canonical signature suffix from jwt.io:
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    # JWT 'jwt-token-example' header (HS256+JWT typ):
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    # JWT.io '1234567890' iss/sub variants:
    "eyJpc3MiOiJqd3QtaW8tZXhhbXBsZSI",
    # Notebook/cheatsheet sentinels caught in iter-7 (used by FP fixtures):
    "NOT_A_REAL", "PLACEHOLDER", "DOC_EXAMPLE",
)

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
    if _PLACEHOLDER_SUBSTR.search(v):                  # 'put your X here', CHANGE_ME, etc.
        return True
    if _PLACEHOLDER_EMBEDDED.search(v):                # 'CpasswordExampleHere', 'YourTokenHere'
        return True
    # interpolation/env-template anywhere in the value -> not a literal secret
    if '${' in v or '{{' in v or '__VAR__' in v or '<your-' in v.lower():
        return True
    # iter-11 FP audit: Symfony env-template '%env(VAR)%' / '%kernel.X%'
    if v.startswith('%') and v.endswith('%') and ('(' in v or '.' in v):
        return True
    return False


def is_known_example(value):
    v = value.strip().strip('"\'`').lower()
    if _is_known_doc_example(v):
        return True
    if _EXAMPLE_SUFFIX.search(v):
        return True
    raw = value.strip().strip('"\'`')
    # iter-7: also catch ALL_CAPS placeholder-words anywhere in the value
    # (e.g. tokens with literal PLACEHOLDER / EXAMPLE / NOT_A_REAL substrings).
    if any(marker in raw for marker in ("PLACEHOLDER", "EXAMPLE", "SAMPLE",
                                        "FAKE", "DUMMY", "CHANGE_ME",
                                        "REPLACE_ME", "REPLACE_WITH",
                                        "NOT_A_REAL", "NOT-A-REAL", "MOCK",
                                        "DOC_EXAMPLE")):
        return True
    # case-sensitive substring match for canonical b64url JWT segments etc.
    for sub in _KNOWN_EXAMPLE_SUBSTR:
        if sub in raw:
            return True
    return is_canonical_sample(v)


# canonical sample hex used in cheatsheets / tutorials: all-sequential
# (0123456789abcdef repeated), all-repeated-block (aaaa1111bbbb2222), or made
# entirely from very low-entropy patterns.
_SEQ_HEX = re.compile(
    r'^(?:0123456789abcdef|abcdef0123456789|fedcba9876543210|fedcba0987654321|'
    r'deadbeef|cafebabe|cafef00d|c0ffee|deadc0de|beefcafe|feedface|baadf00d|'
    r'aabbccdd|aabb1111|aaaa1111|bbbb2222|ccccdddd|11112222|0a0b0c0d|'
    r'1122334455667788|0102030405060708|0a1b2c3d4e5f6071|'
    r'1234567890ab|01020304050607|6f6f6f6f|aaaaaaaa)+[0-9a-f]{0,16}$'
)
# repeat-of-short-block (e.g. ababab..., 11221122..., 0000ffff0000ffff).
# Tightened from 4 to 2 reps so SK<fedcba0987654321><fedcba0987654321> kind
# of canonical Twilio/Mailgun stand-ins are caught.
_REPEAT_HEX = re.compile(r'^([0-9a-f]{4,16})\1{1,}$')


def is_canonical_sample(value):
    """True if the (lowercased, hex) string is a canonical cheatsheet/docs
    sample like '0123456789abcdef0123456789abcdef' or 'cafebabedeadbeef...'.
    Real loot hashes have entropy; samples are decorative."""
    v = value.lower()
    if not re.match(r'^[0-9a-f]+$', v):
        return False
    if _SEQ_HEX.match(v):
        return True
    if _REPEAT_HEX.match(v):
        return True
    return False


# documentation files: cheatsheets / tutorials / README / *.md / *-guide /
# *-storage-tutorial - we apply tighter heuristics on these (still scan, but
# bias HARD against intel-level detectors that fire on prose).
_DOC_NAME = re.compile(
    r'(?i)(?:(?:^|/)(?:readme|changelog|history|contributing|license|notice|'
    r'authors|maintainers|security|code_of_conduct|how[\s_-]?to[\s_-])'
    r'|cheatsheet|cheat-sheet|tutorial|walkthrough|writeup|write-up|'
    r'explained|guide|hardening|reference|primer|intro|overview|playbook|'
    r'documentation|manpage|man[\s_-]?page|wiki|storage-tutorial)'
)


def is_doc_file(path):
    """Heuristic: filename strongly suggests documentation/tutorial content,
    not live loot. Used by intel-level detectors (RECON, BloodHound, ESC#)
    that can't tell prose markup from real tool output."""
    if not path:
        return False
    base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base.endswith((".md", ".markdown", ".rst", ".adoc", ".rdoc", ".tex")):
        return True
    if _DOC_NAME.search(path):
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
# Microsoft's PUBLISHED GPP AES key (so cpassword is always decryptable).
# Reference: MSDN article 2964140 - Microsoft published this key 2014.
GPP_AES_KEY = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"


def decrypt_gpp(cpassword):
    """iter-20: deterministic GPP cpassword decrypt (no operator action needed).
    The cpassword field is base64-then-AES-CBC with the MS-published key + a
    fixed IV (0x00 * 16). The plaintext is UTF-16LE. Returns the password
    string on success, or None on any failure (we deliberately don't surface
    decoder errors to the operator)."""
    import base64
    if not cpassword:
        return None
    # b64 padding fix (GPP can omit trailing '=')
    b64 = cpassword.strip().strip("'\"")
    pad = (4 - len(b64) % 4) % 4
    b64 += "=" * pad
    try:
        ct = base64.b64decode(b64, validate=False)
    except Exception:
        return None
    if len(ct) < 16 or len(ct) % 16 != 0:
        return None
    # Pure-Python AES-CBC decrypt — we ship without cryptography/pycryptodome,
    # so use a minimal AES from stdlib's hashlib + a tiny CBC wrapper.
    # NOTE: Python stdlib does NOT include AES. Try cryptography lib if avail;
    # otherwise skip silently (the operator can still run `gpp-decrypt` manually).
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        key = bytes.fromhex(GPP_AES_KEY)
        iv = b"\x00" * 16
        c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = c.decryptor()
        pt = dec.update(ct) + dec.finalize()
    except Exception:
        return None
    # strip PKCS#7 padding
    if pt and pt[-1] < 16:
        pt = pt[:-pt[-1]]
    try:
        return pt.decode("utf-16-le").rstrip("\x00")
    except Exception:
        return None


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


_TEXTCHARS_B = bytes(range(32, 127)) + b"\t\n\r\f\b"


def is_binary_ish(path, chunk=8192):
    """skip control-char-heavy files: binaries, and 'strings dumps' / prior tool
    output (the htb run re-ingested its own test.txt full of \\x0e\\x0f garbage).
    iter-8: treats valid UTF-8 (with no NUL / no excessive control bytes) as
    text - so winPEAS/linPEAS output with heavy ╔══╝ box-drawing chars and
    other operator-tool unicode output is correctly scanned.
    iter-12: detect UTF-16LE/BE first (PowerShell transcripts, .reg exports,
    Windows event log strings often carry FF FE / FE FF BOM + NULs); a sparse
    NUL pattern alone is no longer treated as binary. Strict 'a single NUL =
    binary' was killing every UTF-16 loot file silently."""
    try:
        with open(path, "rb") as fh:
            block = fh.read(chunk)
    except OSError:
        return True
    if not block:
        return False
    # iter-12: UTF-16 BOM detection. UTF-16LE = FF FE, UTF-16BE = FE FF.
    # If we see the BOM, treat as text (downstream readers must handle).
    if block.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False
    # UTF-16LE without BOM heuristic: file looks like alternating-NUL ASCII
    # (every other byte is 0x00 over a ≥32-byte run). Common for PSReadLine /
    # transcript outputs saved as raw UTF-16.
    if len(block) >= 64:
        even_nuls = sum(1 for i in range(1, min(256, len(block)), 2) if block[i] == 0)
        odd_nuls  = sum(1 for i in range(0, min(256, len(block)), 2) if block[i] == 0)
        # UTF-16LE: high bytes (odd indices) are 0 for ASCII
        if even_nuls > 50 and odd_nuls < 5:
            return False
        # UTF-16BE: high bytes (even indices) are 0 for ASCII
        if odd_nuls > 50 and even_nuls < 5:
            return False
    # try UTF-8 first - if valid AND no excessive control bytes, it's text
    try:
        decoded = block.decode("utf-8-sig")  # iter-12: also strips UTF-8 BOM
        # count control chars (< 0x20 except \n \r \t \f \b)
        ctrl = sum(1 for c in decoded if ord(c) < 32 and c not in "\t\n\r\f\b\x00")
        nuls = decoded.count("\x00")
        # iter-12: a SMALL number of NULs is OK (lsass strings dumps, mixed
        # operator artifacts) as long as the overall text is mostly printable.
        if (ctrl / max(1, len(decoded)) < 0.05
                and nuls / max(1, len(decoded)) < 0.02):
            return False
    except UnicodeDecodeError:
        pass
    # too many NULs -> binary container, not text. Threshold tuned so lsass
    # strings dumps + UTF-16 stay text but raw .bin / .dll get rejected.
    nul_count = block.count(b"\x00")
    if nul_count / max(1, len(block)) > 0.30:
        return True
    # fallback: original ASCII-based byte classifier
    nontext = block.translate(None, _TEXTCHARS_B + b"\x00")
    return len(nontext) / len(block) > 0.30      # raised from 0.10 - the
        # old threshold caught too many legitimate non-ASCII text files


def read_text(path, max_bytes=None):
    """iter-12 unified text reader. Strips UTF-8 BOM, auto-detects UTF-16LE/BE,
    transparently decompresses .gz / .bz2 / .xz. Returns the full text or None
    if the file can't be read. max_bytes caps the returned text size."""
    try:
        # transparent decompression for rotated logs / history backups.
        plow = path.lower()
        if plow.endswith(".gz"):
            import gzip
            opener = lambda: gzip.open(path, "rb")
        elif plow.endswith(".bz2"):
            import bz2
            opener = lambda: bz2.open(path, "rb")
        elif plow.endswith(".xz"):
            import lzma
            opener = lambda: lzma.open(path, "rb")
        else:
            opener = lambda: open(path, "rb")
        with opener() as fh:
            raw = fh.read(max_bytes if max_bytes else -1)
    except OSError:
        return None
    except Exception:
        return None
    if not raw:
        return ""
    # BOM-based detection (most reliable when present)
    if raw.startswith(b"\xff\xfe\x00\x00"):
        enc = "utf-32-le"
        raw = raw[4:]
    elif raw.startswith(b"\x00\x00\xfe\xff"):
        enc = "utf-32-be"
        raw = raw[4:]
    elif raw.startswith(b"\xff\xfe"):
        enc = "utf-16-le"
        raw = raw[2:]
    elif raw.startswith(b"\xfe\xff"):
        enc = "utf-16-be"
        raw = raw[2:]
    elif raw.startswith(b"\xef\xbb\xbf"):
        enc = "utf-8"
        raw = raw[3:]
    else:
        # heuristic: BOM-less UTF-16LE detection (lots of even-position NULs)
        if len(raw) >= 64:
            sample = raw[:512]
            even_nuls = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
            odd_nuls = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
            if even_nuls > 50 and odd_nuls < 5:
                enc = "utf-16-le"
            elif odd_nuls > 50 and even_nuls < 5:
                enc = "utf-16-be"
            else:
                enc = "utf-8"
        else:
            enc = "utf-8"
    try:
        return raw.decode(enc, errors="ignore")
    except Exception:
        try:
            return raw.decode("utf-8", errors="ignore")
        except Exception:
            return None


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
