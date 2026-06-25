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
    ("Stripe key", "HIGH", re.compile(r'(?:sk|rk)_live_[0-9a-zA-Z]{24,}'), None, 0),
    ("SendGrid key", "HIGH", re.compile(r'SG\.[\w\-]{22}\.[\w\-]{43}'), None, 0),
    ("Mailgun key", "HIGH", re.compile(r'key-[0-9a-zA-Z]{32}'), None, 0),
    ("Twilio SID", "HIGH", re.compile(r'SK[0-9a-fA-F]{32}'), None, 0),
    ("npm token", "HIGH", re.compile(r'npm_[A-Za-z0-9]{36}'), None, 0),
    ("DockerHub PAT", "HIGH", re.compile(r'dckr_pat_[A-Za-z0-9_\-]{27}'), None, 0),
    ("JWT", "HIGH", re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'), "16500", 0),
    ("Azure storage key", "HIGH", re.compile(r'(?i)AccountKey=([A-Za-z0-9+/]{86}==)'), None, 1),
    # ---- secrets in well-known shapes -------------------------------------
    ("GPP cpassword", "HIGH", re.compile(r'(?i)cpassword\s*=\s*["\x27]?([A-Za-z0-9+/=]{8,})["\x27]?'), None, 1),
    ("Ansible Vault", "HIGH", re.compile(r'\$ANSIBLE_VAULT;\d+\.\d+;AES256'), None, 0),
    ("Private key", "HIGH", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'), None, 0),
    ("conn string", "MEDIUM", re.compile(r'(?i)(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql|jdbc:[a-z]+)://[^\s"\']{6,}'), None, 0),
    ("URL with creds", "HIGH", re.compile(r'(?i)[a-z][a-z0-9+.\-]*://[^:/\s]+:[^@/\s]+@'), None, 0),
]

# raw-hash names are context-gated (need a hashy keyword nearby) and never fire
# inside an already-matched span (handled by span dedup in analyze()).
_RAW = {"raw MD5/NTLM", "raw SHA1", "raw SHA256", "raw SHA512"}

_HASH_CONTEXT = re.compile(r'(?i)(hash|pass|pwd|ntlm|md5|sha|digest|secret|cred|::|:\d+:|rid)')
# placeholder hex (all same char, classic example) we never want to surface
_JUNK_HEX = re.compile(r'^(0+|f+|deadbeef(?:deadbeef)*|0123456789abcdef.*)$', re.IGNORECASE)
_ENCRYPTED_KEY = re.compile(r'(?i)(ENCRYPTED|Proc-Type:\s*4,ENCRYPTED)')


def _disp(val):
    return val if len(val) <= 70 else val[:70] + "..."


def analyze(path, report):
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

                    # raw hashes: require hashy context to avoid random hex IDs
                    if name in _RAW:
                        if not _HASH_CONTEXT.search(line) or _JUNK_HEX.match(val):
                            continue

                    # canonical documentation/example tokens (AKIA...EXAMPLE etc.)
                    if mode is None and filters.is_known_example(val):
                        continue

                    spans.append((s, e))

                    # ---- NTLM pair: split, recognise blanks, crack the NT ----
                    if name == "NTLM pair (LM:NT)":
                        lm, nt = m.group(1), m.group(2)
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
                        "GPP cpassword" if "GPP" in name else "PATTERNS")
                    hint = None

                    if is_hash:
                        known = known_hashes.lookup(val)
                        if known is not None:
                            report.add("CRITICAL", cat, path, lineno,
                                       f"{name} (DEFAULT = {known!r}): {_disp(val)}",
                                       f"hash of {known!r} - try that password directly, no cracking")
                            continue
                        hint = f"hashcat -m {mode} '{val[:40]}{'...' if len(val) > 40 else ''}' rockyou.txt   (mode {mode})"
                        HASHES.append((mode, name, val, path, lineno))

                    if name == "Private key":
                        enc = _ENCRYPTED_KEY.search(line)
                        hint = ("ENCRYPTED key -> crack: ssh2john <f> > k; hashcat -m 22921 k rockyou.txt"
                                if enc else
                                "plaintext key -> chmod 600 <f>; ssh -i <f> user@ip   (verify: openssl rsa -in <f> -noout)")

                    report.add(sev, cat, path, lineno, f"{name}: {_disp(val)}", hint)
    except Exception:
        pass
