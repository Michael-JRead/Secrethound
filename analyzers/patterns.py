"""patterns.py - secret shapes + hashcat modes + crack-ready hash collection.

Detection is tiered by structural confidence (the trufflehog/gitleaks lesson):
prefix-anchored shapes ($6$, $krb5tgs$, AKIA..., ghp_...) are HIGH confidence
and almost never false; bare hex/base64 are LOW and context-gated so they don't
flood the report. Blank/empty AD hashes are recognised and never sent to crack.
"""
import re
from analyzers import known_hashes
from analyzers import filters
from analyzers import credline

# ── crack-ready hash collection (mode, name, value, file, line) ─────────────
HASHES = []

# Each entry: (name, severity, compiled-regex, hashcat-mode|None, group_index)
# group_index = which regex group holds the crack-ready value (0 = whole match)
PATTERNS = [
    # ---- Linux shadow / unix crypt (prefix-anchored, HIGH confidence) ------
    ("bcrypt", "HIGH", re.compile(r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}'), "3200", 0),
    ("sha512crypt", "HIGH", re.compile(r'\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}'), "1800", 0),
    ("sha256crypt", "HIGH", re.compile(r'\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}'), "7400", 0),
    ("md5crypt", "HIGH", re.compile(r'\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}'), "500", 0),
    ("yescrypt", "HIGH", re.compile(r'\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{20,}'), None, 0),
    ("apr1 (htpasswd)", "HIGH", re.compile(r'\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}'), "1600", 0),
    ("argon2", "HIGH", re.compile(r'\$argon2[id]{1,2}\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+'), None, 0),
    # ---- web app password hashes ------------------------------------------
    ("phpass (WP/phpBB)", "HIGH", re.compile(r'\$[PH]\$[./A-Za-z0-9]{31}'), "400", 0),
    ("Drupal7", "HIGH", re.compile(r'\$S\$[./A-Za-z0-9]{52}'), "7900", 0),
    # ---- Active Directory: Kerberos (THE OSCP+ loot) ----------------------
    ("Kerberoast TGS (RC4)", "HIGH", re.compile(r'\$krb5tgs\$23\$\*[^\s]+\*\$[a-f0-9]{32}\$[a-f0-9]+'), "13100", 0),
    ("Kerberoast TGS (AES128)", "HIGH", re.compile(r'\$krb5tgs\$17\$[^\s]+'), "19600", 0),
    ("Kerberoast TGS (AES256)", "HIGH", re.compile(r'\$krb5tgs\$18\$[^\s]+'), "19700", 0),
    ("AS-REP roast (RC4)", "HIGH", re.compile(r'\$krb5asrep\$23\$[^\s:]+:[a-f0-9]{32}\$[a-f0-9]+'), "18200", 0),
    ("AS-REP roast (AES)", "HIGH", re.compile(r'\$krb5asrep\$1[78]\$[^\s]+'), None, 0),
    ("Kerberos pre-auth", "HIGH", re.compile(r'\$krb5pa\$23\$[^\s]+'), "7500", 0),
    # Timeroasting (NTP MS-SNTP) - hashcat 31300, RustyKey 2024+
    ("Timeroast (SNTP-MS)", "HIGH", re.compile(r'\$sntp-ms\$[a-f0-9]{32}\$[a-f0-9]{40,}'), "31300", 0),
    ("DCC2 (mscash2)", "HIGH", re.compile(r'\$DCC2\$\d+#[^#\s]+#[a-f0-9]{32}'), "2100", 0),
    # ---- AD: NTLM / NetNTLM -----------------------------------------------
    ("NetNTLMv2", "HIGH", re.compile(r'[^\s:]+::[^\s:]*:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]{20,}'), "5600", 0),
    ("NetNTLMv1", "HIGH", re.compile(r'[^\s:]+::[^\s:]*:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}'), "5500", 0),
    ("NTLM pair (LM:NT)", "HIGH", re.compile(r'\b([a-f0-9]{32}):([a-f0-9]{32})\b'), "1000", 2),
    # ---- KeePass (extracted) ----------------------------------------------
    ("KeePass", "HIGH", re.compile(r'\$keepass\$\*\d+\*[^\s]+'), "13400", 0),
    # ---- DB hashes --------------------------------------------------------
    ("MySQL4.1+", "HIGH", re.compile(r'(?<![A-Fa-f0-9])\*[A-F0-9]{40}\b'), "300", 0),
    ("MSSQL 2012+", "HIGH", re.compile(r'0x0200[A-F0-9]{136}'), "1731", 0),
    ("MSSQL 2005", "HIGH", re.compile(r'0x0100[A-F0-9]{88}'), "132", 0),
    ("Cisco type8", "HIGH", re.compile(r'\$8\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}'), "9200", 0),
    ("Cisco type9", "HIGH", re.compile(r'\$9\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}'), "9300", 0),
    # ---- raw hashes (LOW confidence - context-gated below) -----------------
    ("raw MD5/NTLM", "MEDIUM", re.compile(r'(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])'), "0", 0),
    ("raw SHA1", "MEDIUM", re.compile(r'(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])'), "100", 0),
    ("raw SHA256", "MEDIUM", re.compile(r'(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])'), "1400", 0),
    ("raw SHA512", "MEDIUM", re.compile(r'(?<![a-f0-9])[a-f0-9]{128}(?![a-f0-9])'), "1700", 0),
    # ---- cloud / vendor tokens (prefix-anchored, HIGH) --------------------
    ("AWS access key", "HIGH", re.compile(r'(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[0-9A-Z]{16}'), None, 0),
    ("AWS secret", "HIGH", re.compile(r'(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{40})'), None, 1),
    ("Google API key", "HIGH", re.compile(r'AIza[0-9A-Za-z_\-]{35}'), None, 0),
    ("Google OAuth", "HIGH", re.compile(r'ya29\.[0-9A-Za-z_\-]{20,}'), None, 0),
    ("GitHub token", "HIGH", re.compile(r'gh[pousr]_[A-Za-z0-9]{36}'), None, 0),
    ("GitHub PAT (fine)", "HIGH", re.compile(r'github_pat_[A-Za-z0-9_]{82}'), None, 0),
    ("GitLab PAT", "HIGH", re.compile(r'glpat-[0-9A-Za-z_\-]{20}'), None, 0),
    ("Slack token", "HIGH", re.compile(r'xox[baprse]-[0-9A-Za-z-]{10,}'), None, 0),
    ("Stripe key", "HIGH", re.compile(r'(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}'), None, 0),
    # iter-11: Stripe publishable key (low sev: PK is meant to be public, but
    # operators sometimes paste -test keys mistaking them for usable)
    ("Stripe publishable", "LOW", re.compile(r'\bpk_(?:live|test)_[0-9a-zA-Z]{24,}\b'), None, 0),
    # iter-11: Stripe webhook signing secret (forge HMAC-signed webhooks).
    ("Stripe webhook secret", "HIGH", re.compile(r'\bwhsec_[A-Za-z0-9]{32,64}\b'), None, 0),
    # iter-11: Discord webhook URL (unauth POST as bot).
    ("Discord webhook", "HIGH", re.compile(
        r'https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{40,100}'),
     None, 0),
    # iter-11: Tailscale auth key (machine onboard / OAuth client).
    ("Tailscale authkey", "HIGH", re.compile(
        r'tskey-(?:auth|client|api|scim|webhook)-[A-Za-z0-9]{6,}-[A-Za-z0-9]{16,}'), None, 0),
    # iter-11: HashiCorp Cloudflared connector token (b64; gated by typed var).
    ("Cloudflared tunnel token", "HIGH", re.compile(
        r'(?i)\bcloudflared\b[^\n]{0,200}?--token\s+([A-Za-z0-9+/=._\-]{40,})'), None, 1),
    # iter-11: HeidiSQL / DBeaver / Navicat hex(...) password envelope (XOR
    # reversible with their published key).
    ("HeidiSQL hex password", "HIGH", re.compile(
        r'(?i)"(?:Password|EncryptedPassword)"\s*[:=]\s*"hex\(([0-9a-fA-F]{8,})\)"'), None, 1),
    ("SendGrid key", "HIGH", re.compile(r'SG\.[\w\-]{22}\.[\w\-]{43}'), None, 0),
    ("Mailgun key", "HIGH", re.compile(r'key-[0-9a-zA-Z]{32}'), None, 0),
    ("Twilio SID", "HIGH", re.compile(r'SK[0-9a-fA-F]{32}'), None, 0),
    ("npm token", "HIGH", re.compile(r'npm_[A-Za-z0-9]{36}'), None, 0),
    ("DockerHub PAT", "HIGH", re.compile(r'dckr_pat_[A-Za-z0-9_\-]{27}'), None, 0),
    ("JWT", "HIGH", re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'), "16500", 0),
    ("Azure storage key", "HIGH", re.compile(r'(?i)AccountKey=([A-Za-z0-9+/]{86}==)'), None, 1),
    # ---- secrets in well-known shapes -------------------------------------
    # GPP cpassword: word-bounded `cpassword` only (so `SQLSVCPASSWORD` does NOT
    # match), and the value must be >= 24 b64 chars (one AES block padded).
    ("GPP cpassword", "HIGH", re.compile(r'(?i)\bcpassword\s*=\s*["\x27]?([A-Za-z0-9+/=]{24,})["\x27]?'), None, 1),
    ("Password Safe v3", "HIGH", re.compile(r'\$pwsafe\$\*3\*[a-fA-F0-9]{64}\*\d+\*[a-fA-F0-9]{64}'), "5200", 0),
    ("KeePass2 hash", "HIGH", re.compile(r'\$keepass\$\*[12]\*\d+\*[a-fA-F0-9]+\*[a-fA-F0-9]+'), "13400", 0),
    ("VNC reg password", "HIGH", re.compile(r'(?i)"?Password"?\s*=\s*hex:([0-9a-fA-F]{2}(?:[,\s][0-9a-fA-F]{2}){7})'), None, 1),
    ("Ansible Vault", "HIGH", re.compile(r'\$ANSIBLE_VAULT;\d+\.\d+;AES256'), None, 0),
    # iter-11: SAMLResponse blob (SSO abuse - replay / sign / inject). Bound
    # to a SAMLResponse field name to avoid base64-everywhere FPs. Accept both
    # raw `=` padding and URL-encoded `%3D`.
    ("SAMLResponse blob", "HIGH", re.compile(
        r'(?i)SAMLResponse(?:=|"\s*:\s*"|\s*:\s*"|"\s*,\s*"value"\s*:\s*")\s*"?'
        r'([A-Za-z0-9+/]{200,}(?:={0,2}|(?:%3D){0,2}))'), None, 1),
    ("Private key", "HIGH", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'), None, 0),
    # `conn string` (bare DB URI without user:pass) was removed in iter-7: the
    # FP-audit produced 22 FPs on innocuous URLs (redis://redis:6379/0,
    # mongodb://mongo:27017/sessions). The HIGH `URL with creds` rule below
    # already covers the credentialed case - which is the only one with a
    # secret to leak. No true positives lost.
    ("URL with creds", "HIGH", re.compile(r'(?i)[a-z][a-z0-9+.\-]*://[^:/\s]+:[^@/\s]+@'), None, 0),
]

# raw-hash names are context-gated (need a hashy keyword nearby) and never fire
# inside an already-matched span (handled by span dedup in analyze()).
_RAW = {"raw MD5/NTLM", "raw SHA1", "raw SHA256", "raw SHA512"}

# POSITIVE context: a hashy keyword near the value (real loot context).
_HASH_CONTEXT = re.compile(r'(?i)(hash|pass|pwd|ntlm|md5|sha|digest|secret|cred|::|:\d+:|rid)')
# NEGATIVE context: even with a hash word on the line, these markers mean the
# hex is a content-integrity / cache-key / commit-SHA / package-checksum, NOT
# a credential. From the iter-7 FP audit: 36+ FPs across raw MD5/SHA1/SHA256
# (Python `--hash=sha256:`, npm `integrity:`, `EXPECTED_SHA256=`, `MD5 (file)`
# gnu md5sum output, `etag`, `nonce=`, `csrf token rotated`, `GIT_COMMIT_HASH`,
# `digest_kind=md5`, `"shasum":`, `"content-hash":`, source-map `sourceMappingURL`).
_HASH_NEG_CONTEXT = re.compile(
    r'(?i)(?:--hash\s*=\s*sha|integrity\s*[:=]|integrity\s*"\s*:|'
    r'\bEXPECTED_(?:MD5|SHA\d*|HASH)\b|\bGIT_COMMIT\b|\bcommit[\s_-]?(?:sha|hash|id)\b|'
    r'\betag\b|\bcsrf\b|\bnonce\b|\bcache[\s_-]?key\b|'
    r'\bcontent[\s_-]?hash\b|"shasum"\s*:|"sha\d+"\s*:|'
    r'\bdigest[\s_-]?kind\b|\bdigest\s*=|digest_algo|'
    r'\bMD5\s*\(|\bSHA\d*\s*\(|\bSHA\d*\s+checksum\b|\bsha\d+\s*=|\bmd5\s*=|'
    r'\bsourceMappingURL\b|sha\d+:[a-f0-9]|\bfingerprint\b|'
    r'\bchecksum\b|\bSRI[\s_-]?hash\b|'
    # iter-7 round-2: nmap ssl-cert output (X.509 fingerprints), TLS cert
    # SHA256/SHA1 thumbprints, hashcat benchmark/example output, GPO/CSV manifest
    # column headers, OpenSSL fingerprint -sha256 output.
    r'\bssl[\s_-]?cert\b|\bX\.509\b|\bx509\b|\bthumbprint\b|\bSubject\s+Public\s+Key\b|'
    r'\bnmap\b|\bbenchmark\b|\bbenchmarking\b|\btest\s+vector\b|\bexample\s+hashes?\b|'
    r'\btls[\s_-]?fingerprint\b|\bcert[\s_-]?fingerprint\b|"thumb"\s*:|'
    r'\bPublic\s+Key\b|\bissuer\b|\bsubject\b|\bvalidity\b|\bnot\s+(?:before|after)\b|'
    # CSV/manifest column header rows that produce 32-hex-shaped IDs (GPO/AD
    # backup manifests, asset CSVs, vite chunk hash logs):
    r'\bmanifest\b|\bgpo[\s_-]?backup\b|\bbackup[\s_-]?id\b|\basset[\s_-]?hash\b|'
    r'\bvite\s*:|\bchunk\b)'
)
# package-manifest / lock-file paths that ship content-addressed hashes for
# every dep. We apply this on PATH not LINE (lock files are huge tables).
_LOCK_FILE = re.compile(
    r'(?i)(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.ya?ml|composer\.lock|'
    r'Cargo\.lock|go\.sum|Pipfile\.lock|poetry\.lock|Gemfile\.lock|pubspec\.lock|'
    r'gradle.*\.lock|requirements.*\.lock|conda-lock\.ya?ml|stack\.ya?ml\.lock|'
    r'mix\.lock|elm-stuff/.*|flake\.lock|deno\.lock|registry-auth\.lock|.*-lock\..*)'
    r'|\.lock(?:\.\w+)?$'
)
# raw hex in a source-code comment is documentation/example, never live loot
# (real hashdump/secretsdump rows are never comment-prefixed).
_CODE_COMMENT = re.compile(r'^\s*(#|//|\*|/\*|--\s|;)')
# placeholder hex (all same char, classic example) we never want to surface
_JUNK_HEX = re.compile(r'^(0+|f+|deadbeef(?:deadbeef)*|0123456789abcdef.*)$', re.IGNORECASE)
_ENCRYPTED_KEY = re.compile(r'(?i)(ENCRYPTED|Proc-Type:\s*4,ENCRYPTED)')
# pwdump/secretsdump context for the LM:NT pair: real dumps either show the
# trailing `:::`, a leading `user:rid:` prefix, or sit beside the literal word
# "NTLM"/"ntds"/"sam"/"hash". Without one of these the bare 32:32 hex pair
# matches benign manifest rows (asset MD5:MD5 lists, vite chunk hashes, etc.)
# - 17 FPs from the iter-7 audit.
_NTLM_PAIR_CONTEXT = re.compile(
    r'(?i)(:::\s*$|^\s*(?:\S+\\)?\S+:\d{1,7}:|\bNTLM\b|\bNTDS\b|\bSAM\b|'
    r'\bsecretsdump\b|\bpwdump\b|\bhashdump\b|\bDCSync\b|aad3b435b51404eeaad3b435b51404ee)'
)


def _disp(val):
    return val if len(val) <= 70 else val[:70] + "..."


def analyze(path, report, store=None):
    # iter-7: lock files are content-addressed dep manifests - thousands of
    # 32/40/64-hex integrity hashes per file. Skip the hash-shaped detectors
    # entirely. Real cred leaks in lock files are extraordinarily rare; the
    # FP-audit found 100% noise there.
    _skip_hashes = bool(_LOCK_FILE.search(path or ""))
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                # pwdump row -> bind username to NT hash (and skip generic match
                # so the same hash isn't ALSO reported unbound). Detail string is
                # identical to ext_secretsdump so _dedup() collapses the overlap.
                pw = credline.is_pwdump_row(line)
                if pw:
                    user, nt, _dom = pw
                    known = known_hashes.lookup(nt)
                    if known is not None:
                        report.add("CRITICAL", "CRED PAIRS", path, lineno,
                                   f"{user} NT=DEFAULT '{known}' ({nt[:12]}...)",
                                   f"log in directly: netexec smb <DC-IP> -u '{user}' -p '{known}'")
                    else:
                        report.add("HIGH", "PASSWORD HASHES", path, lineno,
                                   f"NTLM (NT) {user}: {nt}",
                                   f"PtH: netexec smb <DC-IP> -u '{user}' -H {nt}  |  crack: hashcat -m 1000 <nt> rockyou.txt")
                        HASHES.append(("1000", "NTLM", nt, path, lineno))
                    continue
                spans = []   # (start, end) of every match already taken on this line
                for name, sev, rx, mode, gi in PATTERNS:
                    m = rx.search(line)
                    if not m:
                        continue
                    # skip sub-matches: a raw hash inside an NTLM pair, the pair
                    # inside a NetNTLMv2 blob, the checksum inside a krb ticket...
                    s, e = m.span(0)
                    if any(s >= bs and e <= be for bs, be in spans):
                        continue
                    full = m.group(0)
                    val = m.group(gi) if gi and m.lastindex and gi <= m.lastindex else full

                    # raw hashes: require hashy context to avoid random hex IDs.
                    # iter-7: also reject when the line carries a content-integrity
                    # / cache / commit / etag / shasum / --hash=sha:NN / MD5(file)
                    # marker - those are content-addressed hashes, not credentials.
                    if name in _RAW:
                        if (not _HASH_CONTEXT.search(line) or _JUNK_HEX.match(val)
                                or _CODE_COMMENT.match(line)
                                or _HASH_NEG_CONTEXT.search(line)):
                            continue

                    # NTLM (LM:NT) pair: a colon-joined 32hex:32hex token also
                    # matches md5(asset):md5(thumb) dedup rows, file-checksum
                    # CSVs, vite chunk maps, etc. Real NTLM dumps always carry
                    # very specific context (a :::, user:rid: prefix, or a
                    # 'NTLM'/'NTDS'/'SAM'/'secretsdump' keyword, or the blank-LM
                    # marker hash). Require one of those to fire - iter-7 FP
                    # audit killed 17 FPs here.
                    # Also reject negative context (gpo_backup_manifest.csv,
                    # nmap ssl-cert thumbprints, vite chunk hashes) and the
                    # lock-file gate above.
                    if name == "NTLM pair (LM:NT)":
                        if (not _NTLM_PAIR_CONTEXT.search(line)
                                or _HASH_NEG_CONTEXT.search(line)
                                or _skip_hashes):
                            continue
                    # Lock-file gate: all hash-shaped detectors off.
                    if _skip_hashes and name in (
                            "raw MD5/NTLM", "raw SHA1", "raw SHA256", "raw SHA512",
                            "bcrypt", "sha512crypt", "sha256crypt", "md5crypt",
                            "yescrypt", "apr1 (htpasswd)", "argon2", "phpass (WP/phpBB)",
                            "Drupal7", "Kerberoast TGS (RC4)", "Kerberoast TGS (AES128)",
                            "Kerberoast TGS (AES256)", "AS-REP roast (RC4)",
                            "AS-REP roast (AES)", "Kerberos pre-auth",
                            "Timeroast (SNTP-MS)", "DCC2 (mscash2)", "NetNTLMv2",
                            "NetNTLMv1", "NTLM pair (LM:NT)", "KeePass",
                            "MySQL4.1+", "MSSQL 2012+", "MSSQL 2005",
                            "Cisco type8", "Cisco type9", "GPP cpassword",
                            "Mailgun key", "Twilio SID", "Stripe key",
                            "SendGrid key", "Google API key", "Google OAuth",
                            "Slack token", "JWT", "Azure storage key",
                            "GitHub token", "GitHub PAT (fine)", "GitLab PAT",
                            "npm token", "DockerHub PAT", "AWS access key",
                            "AWS secret", "Password Safe v3", "KeePass2 hash",
                            "VNC reg password", "Ansible Vault"):
                        continue

                    # canonical documentation/example tokens (AKIA...EXAMPLE etc.).
                    # iter-7: also reject for HASHED secrets (bcrypt/apr1/etc.)
                    # since well-known doc-example hashes are in _KNOWN_EXAMPLES too.
                    if filters.is_known_example(val):
                        continue
                    # iter-9: embedded placeholder (CamelCase 'ExampleKey',
                    # 'YourTokenHere', 'CpasswordExampleHere', etc.) - safe
                    # against real passwords because the regex requires both a
                    # placeholder-marker word AND a secret-noun word.
                    if filters._PLACEHOLDER_EMBEDDED.search(val):
                        continue
                    # iter-7: canonical cheatsheet/tutorial hex (the literal
                    # '0123456789abcdef0123456789abcdef' run, 'deadbeef...',
                    # 'cafebabe...', etc.) should never fire as a hash.
                    if re.match(r'^[a-f0-9]{16,}$', val.lower()) and filters.is_canonical_sample(val):
                        continue
                    # iter-7: doc files (README, cheatsheets, tutorials, .md /
                    # .rst / .adoc): suppress the noisy hash patterns that fire
                    # on sample blobs. We still want to catch real hashes IF the
                    # operator stores them in a .md note (Cicada/Resolute do
                    # this), so we ONLY skip when the value also looks doc-shaped:
                    # the full hex run is canonical-sample, or the line carries
                    # markdown-bullet/inline-code formatting around it.
                    if filters.is_doc_file(path) and name in (
                            "Kerberoast TGS (RC4)", "Kerberoast TGS (AES128)",
                            "Kerberoast TGS (AES256)", "AS-REP roast (RC4)",
                            "AS-REP roast (AES)", "Kerberos pre-auth",
                            "Timeroast (SNTP-MS)", "md5crypt", "sha512crypt",
                            "sha256crypt", "bcrypt", "apr1 (htpasswd)",
                            "GPP cpassword", "MSSQL 2012+", "MSSQL 2005"):
                        # only skip if the line looks like prose / markdown
                        # (indented bullet, inline code fence, or 'example:'/'sample:'/'e.g.')
                        if re.search(r'(?i)^\s*[-*]\s|`[^`]*`|e\.g\.|\bexample\b|\bsample\b|\btutorial\b', line):
                            continue
                        # iter-81: also skip when the hash's HEX tail is a
                        # canonical cheatsheet run ('0123456789abcdef...' /
                        # 'deadbeef...' / repeated blocks). Docs authors put
                        # these in Kerberoast hash samples all the time
                        # ($krb5tgs$23$*svc$DOM$SPN*$<canonical-hex>$<canonical-hex>).
                        # The line-content gate above misses these because
                        # the sample line itself carries no prose markers.
                        _hex_tails = re.findall(r'[a-f0-9]{16,}', full or "")
                        if _hex_tails and all(filters.is_canonical_sample(h)
                                              for h in _hex_tails):
                            continue
                    # iter-9: Ansible Vault marker is a short, distinctive header
                    # ('$ANSIBLE_VAULT;1.1;AES256') - in doc files it's ALWAYS
                    # demonstrating the format, never real loot. Unconditional
                    # skip on doc files (no line-content gate needed).
                    if name == "Ansible Vault" and filters.is_doc_file(path):
                        continue

                    # URL with creds: drop template/placeholder/default credentials
                    # (e.g. amqp://guest:guest@..., postgres://${DB_USER}:${DB_PASSWORD}@...,
                    # https://acme:${NUGET_PAT}@..., mysql://wp:CHANGE_THIS_PASSWORD@...).
                    if name == "URL with creds":
                        cm = re.search(r'://([^:/?\s@]+):([^@/?\s]+)@', full)
                        if cm:
                            u, p = cm.group(1), cm.group(2)
                            if filters.is_placeholder(u) and filters.is_placeholder(p):
                                continue
                            if filters.is_placeholder(p):
                                continue
                            if '${' in u or '${' in p or '{{' in u or '{{' in p:
                                continue
                            # both halves are placeholder-shaped dev users (devuser, dbuser):
                            if filters.is_placeholder(u):
                                continue

                    # vendor token patterns whose hex tail is canonical-sample
                    # (key-0123456789abcdef..., SK0123..., sk_live_0123...): the
                    # prefix matches the brand but the body is a cheatsheet example.
                    if name in ("Mailgun key", "Twilio SID", "Stripe key",
                                "SendGrid key", "GitHub token", "GitHub PAT (fine)",
                                "GitLab PAT", "Slack token", "npm token",
                                "DockerHub PAT", "Google API key", "Google OAuth",
                                "AWS access key", "Azure storage key"):
                        # strip the brand prefix and check the body for canonical hex
                        body = re.sub(r'^[A-Za-z][A-Za-z0-9_-]{1,15}[-_.]', '', val)
                        if filters.is_canonical_sample(body):
                            continue
                        if "PLACEHOLDER" in val or "EXAMPLE" in val:
                            continue

                    # NTLM hash (NT) bare value: 32-hex with hashy context. Drop
                    # canonical samples (7d7930... = md5('foobar'), and the
                    # cheatsheet 0123... runs).
                    if name in ("raw MD5/NTLM", "NTLM hash (NT)") and filters.is_canonical_sample(val):
                        continue

                    spans.append((s, e))

                    # ---- NTLM pair: split, recognise blanks, crack the NT ----
                    if name == "NTLM pair (LM:NT)":
                        lm, nt = m.group(1), m.group(2)
                        # iter-7: doc files (hardening guides) show the blank-LM/NT
                        # pair as an *educational example* of an empty password -
                        # not loot. Suppress.
                        if filters.is_doc_file(path):
                            continue
                        note_nt = filters.blank_hash_note(nt)
                        if filters.is_blank_hash(nt):
                            report.add("MEDIUM", "PASSWORD HASHES", path, lineno,
                                       f"NTLM pair (NT is blank): {lm}:{nt}", note_nt)
                            continue
                        known = known_hashes.lookup(nt)
                        if known is not None:
                            report.add("CRITICAL", "PASSWORD HASHES", path, lineno,
                                       f"NTLM (DEFAULT = {known!r}): {nt}",
                                       f"NT hash of {known!r} - just log in: nxc smb <dc> -u <user> -p '{known}'")
                            continue
                        lm_note = "" if filters.is_blank_hash(lm) else " (LM half also crackable: hashcat -m 3000)"
                        report.add(sev, "PASSWORD HASHES", path, lineno,
                                   f"NTLM hash (NT): {nt}",
                                   f"PtH now: nxc smb <dc> -u <user> -H {nt}   |  or crack: hashcat -m 1000 <nt> rockyou.txt{lm_note}")
                        HASHES.append(("1000", "NTLM", nt, path, lineno))
                        continue

                    # ---- blank single hash recognition -----------------------
                    blank = filters.blank_hash_note(val)
                    if blank:
                        report.add("MEDIUM", "PASSWORD HASHES", path, lineno,
                                   f"{name}: {val}", blank)
                        continue

                    is_hash = mode is not None and name not in (
                        "AWS secret", "JWT", "GPP cpassword")
                    cat = "PASSWORD HASHES" if is_hash else (
                        "PRIVATE KEYS" if "Private key" in name else
                        "GPP cpassword" if "GPP" in name else
                        "ASSIGNED SECRETS" if name == "VNC reg password" else "PATTERNS")
                    hint = None
                    if name == "VNC reg password":
                        # 8-byte single-DES with fixed key (Cascade-style) - fully offline.
                        hint = ("vncpwd $(printf '" + val.replace(",", "") +
                                "' | xxd -r -p) | strings   # or jeroennijhof/vncpwd")

                    if is_hash:
                        known = known_hashes.lookup(val)
                        if known is not None:
                            report.add("CRITICAL", cat, path, lineno,
                                       f"{name} (DEFAULT = {known!r}): {_disp(val)}",
                                       f"hash of {known!r} - try that password directly, no cracking")
                            continue
                        hint = f"hashcat -m {mode} '{val[:40]}{'...' if len(val) > 40 else ''}' rockyou.txt   (mode {mode})"
                        HASHES.append((mode, name, val, path, lineno))
                        # iter-24: AS-REP / Kerberoast hashes embed the user in
                        # their canonical form. Extract and emit an Evidence
                        # binding so correlate.py R-CRACK chains can name the
                        # user in their command (and the user shows up in
                        # users.txt for sprays once cracked).
                        if store is not None and name.startswith(
                                ("AS-REP roast", "Kerberoast TGS")):
                            urx = re.search(
                                r'\$krb5(?:asrep|tgs)\$\d+\$(?:\*)?'
                                r'([A-Za-z0-9_.\-]{1,50})'
                                r'(?:[@:$*])', val)
                            if urx:
                                u_ = urx.group(1)
                                if u_ and not u_.lower().startswith(
                                        ("dom", "domain", "realm")):
                                    from analyzers.ingest.evidence import Evidence as _Ev
                                    store.add(_Ev(kind="user", user=u_,
                                                  fact=("kerberoastable" if
                                                        name.startswith("Kerberoast") else
                                                        "asreproastable"),
                                                  source=path, line=lineno))

                    if name == "Private key":
                        enc = _ENCRYPTED_KEY.search(line)
                        hint = ("ENCRYPTED key -> crack: ssh2john <f> > k; hashcat -m 22921 k rockyou.txt"
                                if enc else
                                "plaintext key -> chmod 600 <f>; ssh -i <f> user@ip   (verify: openssl rsa -in <f> -noout)")

                    report.add(sev, cat, path, lineno, f"{name}: {_disp(val)}", hint)
    except Exception:
        pass
