"""patterns.py - secret shapes + hashcat modes + crack-ready hash collection."""
import re
from analyzers import known_hashes
PATTERNS = [
    ("bcrypt","HIGH",re.compile(r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}'),"3200"),
    ("sha512crypt","HIGH",re.compile(r'\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}'),"1800"),
    ("sha256crypt","HIGH",re.compile(r'\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}'),"7400"),
    ("md5crypt","HIGH",re.compile(r'\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}'),"500"),
    ("argon2","HIGH",re.compile(r'\$argon2[id]{1,2}\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+'),None),
    ("NetNTLMv2","HIGH",re.compile(r'[^\s:]+::[^\s:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]{20,}'),"5600"),
    ("NTLM pair","HIGH",re.compile(r'\b[a-f0-9]{32}:[a-f0-9]{32}\b'),"1000"),
    ("raw MD5/NTLM","MEDIUM",re.compile(r'(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])'),"0"),
    ("raw SHA1","MEDIUM",re.compile(r'(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])'),"100"),
    ("raw SHA256","MEDIUM",re.compile(r'(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])'),"1400"),
    ("AWS access key","HIGH",re.compile(r'AKIA[0-9A-Z]{16}'),None),
    ("AWS secret","HIGH",re.compile(r'(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}'),None),
    ("JWT","HIGH",re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'),None),
    ("Slack token","HIGH",re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}'),None),
    ("GitHub token","HIGH",re.compile(r'gh[pousr]_[A-Za-z0-9]{36}'),None),
    ("GPP cpassword","HIGH",re.compile(r'(?i)cpassword\s*=\s*["\x27]?([A-Za-z0-9+/=]{8,})["\x27]?'),None),
    ("Private key hdr","HIGH",re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'),None),
    ("conn string","MEDIUM",re.compile(r'(?i)(mongodb|postgres(?:ql)?|mysql|redis|amqp)://[^\s"\']{6,}'),None),
    ("URL with creds","HIGH",re.compile(r'(?i)[a-z]+://[^:/\s]+:[^@/\s]+@'),None),
]
_HASH_CONTEXT = re.compile(r'(?i)(hash|pass|pwd|ntlm|md5|sha|digest|secret|cred|::)')
HASHES = []
def analyze(path, report):
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                for name, sev, rx, mode in PATTERNS:
                    m = rx.search(line)
                    if not m: continue
                    val = m.group(0)
                    if name.startswith("raw ") and not _HASH_CONTEXT.search(line): continue
                    disp = val if len(val) <= 70 else val[:70] + "..."
                    is_hash = mode is not None
                    cat = "PASSWORD HASHES" if is_hash else "PATTERNS"
                    hint = None
                    if is_hash:
                        known = known_hashes.lookup(val)
                        if known is not None:
                            report.add("MEDIUM", cat, path, lineno, f"{name} (DEFAULT = {known!r}): {disp}", f"hash of {known!r} - try that password directly, no cracking")
                            continue
                        hint = f"hashcat -m {mode} '{val[:40]}{'...' if len(val)>40 else ''}' rockyou.txt   (mode {mode})"
                        HASHES.append((mode, name, val, path, lineno))
                    report.add(sev, cat, path, lineno, f"{name}: {disp}", hint)
    except Exception: pass
