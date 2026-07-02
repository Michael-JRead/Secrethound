"""configs.py - structured-config analyzers that need real parsing, not regex.

For now: Windows unattend.xml / Autounattend.xml / sysprep.xml. The Microsoft-
canonical encoding for <PlainText>false</PlainText> passwords is
   base64( UTF-16LE( password + parent_element_name ) )
where parent_element_name is exactly the name of the enclosing element -
'AdministratorPassword' for the matching block, 'Password' for AutoLogon /
LocalAccount Password blocks. Some third-party producers (LaZagne et al.)
omit the suffix; we try strip-suffix AND no-suffix and emit the more
believable result.
"""
import base64
import os
import re
import xml.etree.ElementTree as ET

from analyzers import filters
from analyzers.ingest.evidence import Evidence

_UNATTEND_HINT = re.compile(
    r"(?i)urn:schemas-microsoft-com:unattend|<unattend\b|<AutoLogon\b|<AdministratorPassword\b")


def _strip_ns(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _decode_value(b64, parent_name):
    """Decode an unattend <Value>. Returns (password, source) or None.
    iter-17 (corpus mine wkl2kkzn5): also try ASCII / UTF-8 fallback because
    some THM rooms / winPEAS output / third-party unattend generators store
    the password as plain base64-of-ASCII rather than the MS-canonical
    base64-of-UTF16LE form. We attempt UTF-16LE first (canonical), then
    fall through to UTF-8 / latin-1 for the THM-style shape."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    suffix = parent_name or ""
    # canonical Microsoft path: UTF-16LE
    try:
        text = raw.decode("utf-16-le")
        if text:
            if suffix and text.endswith(suffix) and len(text) > len(suffix):
                return text[:-len(suffix)], "b64-utf16le, parent-suffix stripped"
            if text.isprintable():
                return text, "b64-utf16le, no suffix"
    except Exception:
        pass
    # iter-17 ASCII / UTF-8 fallback (THM 'Windows PrivEsc' / winPEAS shape)
    for enc, note in (("utf-8", "b64-ascii (THM/winPEAS shape)"),
                       ("latin-1", "b64-latin1 fallback")):
        try:
            text = raw.decode(enc)
            if (text and text.isprintable() and 3 <= len(text) <= 80):
                return text, note
        except Exception:
            continue
    return None


def _emit_password(report, store, path, parent, pw, note):
    if not pw or filters.is_placeholder(pw):
        return
    label = parent or "unattend password"
    detail = f"unattend {label}: {pw}  ({note})"
    # iter-159: shell-escape pw for parity with the rest of the ingest
    # layer (iter-140/141/158). unattend passwords are frequently
    # copy-pasted apostrophe-bearing values (P@ssw0rd's, etc.).
    _pw_sh = pw.replace("'", "'\\''")
    report.add("CRITICAL", "CRED PAIRS", path, None, detail,
               hint=("Windows unattend password recovered - log in directly: "
                     f"netexec smb <DC-IP> -u Administrator -p '{_pw_sh}'"))
    if store is not None:
        store.add(Evidence(kind="plaintext", user="Administrator", plaintext=pw,
                           source=path))


_PWBLOCK = re.compile(
    r'<(AdministratorPassword|Password)\b[^>]*>(.*?)</\1>',
    re.IGNORECASE | re.DOTALL)
_PWVALUE = re.compile(r'<Value\b[^>]*>([^<]*)</Value>', re.IGNORECASE)
_PWPLAIN = re.compile(r'<PlainText\b[^>]*>\s*(true|false)\s*</PlainText>', re.IGNORECASE)


def _walk_unattend_regex(path, report, store):
    """Fallback when ElementTree refuses (e.g. malformed real-world unattend with
    undeclared namespace prefixes). Uses the same decode recipe; the structure is
    flat enough that a regex grouping by Password element is reliable."""
    try:
        with open(path, "r", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return 0
    n = 0
    for m in _PWBLOCK.finditer(text):
        suffix = m.group(1)         # 'AdministratorPassword' or 'Password'
        body = m.group(2)
        vm = _PWVALUE.search(body)
        pm = _PWPLAIN.search(body)
        if not vm:
            continue
        value = vm.group(1).strip()
        if not value or value == "*SENSITIVE*DATA*DELETED*":
            continue
        if pm and pm.group(1).lower() == "true":
            _emit_password(report, store, path, suffix, value, "PlainText=true")
            n += 1
        else:
            dec = _decode_value(value, suffix)
            if dec:
                pw, note = dec
                _emit_password(report, store, path, suffix, pw, note)
                n += 1
    if n:
        report.add("INFO", "RECON", path, None,
                   f"Windows unattend.xml parsed: {n} password(s) recovered (regex fallback)")
    return n


def _walk_unattend(path, report, store):
    try:
        tree = ET.parse(path)
    except OSError:
        return 0
    except ET.ParseError:
        return _walk_unattend_regex(path, report, store)
    n = 0
    for elem in tree.iter():
        tag = _strip_ns(elem.tag)
        # Password blocks contain a <Value> and a <PlainText>
        if tag not in ("AdministratorPassword", "Password"):
            continue
        # parent_name used as the suffix when decoding
        # for the AutoLogon's <Password>, suffix is 'Password'
        # for <AdministratorPassword>, suffix is 'AdministratorPassword'
        suffix = tag
        value, plain = None, None
        for child in elem:
            c = _strip_ns(child.tag)
            if c == "Value":
                value = (child.text or "").strip()
            elif c == "PlainText":
                plain = (child.text or "").strip().lower()
        if not value or value in ("", "*SENSITIVE*DATA*DELETED*"):
            continue
        if plain == "true":
            _emit_password(report, store, path, tag, value, "PlainText=true")
            n += 1
        else:
            dec = _decode_value(value, suffix)
            if dec:
                pw, note = dec
                _emit_password(report, store, path, tag, pw, note)
                n += 1
    if n:
        report.add("INFO", "RECON", path, None,
                   f"Windows unattend.xml parsed: {n} password(s) recovered")
    return n


def detect(path, head):
    base = os.path.basename(path).lower()
    if base in ("unattend.xml", "autounattend.xml", "sysprep.xml"):
        return True
    return bool(_UNATTEND_HINT.search(head))


def analyze(path, report, store=None):
    if detect(path, ""):                  # cheap by-name short circuit
        return _walk_unattend(path, report, store)
    # iter-8: binary file-magic detection for known loot blob formats
    n = _binary_magic_scan(path, report, store)
    if n:
        return n
    try:
        with open(path, "r", errors="ignore") as fh:
            head = fh.read(2048)
    except OSError:
        return 0
    if not _UNATTEND_HINT.search(head):
        return 0
    return _walk_unattend(path, report, store)


# Known credential/ticket/keystore file-magic markers - operator loot dirs
# routinely carry .pfx/.kdbx/.kirbi/.ccache without obvious extensions, and
# even when extension is present we want a concrete crackable-hash next step.
_BINARY_MAGIC = [
    # (hex magic bytes, klass, severity, next-step hint)
    (b"\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5",
     "KeePass KDBX v2/3/4 database",
     "HIGH",
     "keepass2john <file> > k.hash; hashcat -m 13400 k.hash rockyou.txt"),
    (b"\x03\xD9\xA2\x9A\x66\xFB\x4B\xB5",
     "KeePass KDBX v2 pre-release database",
     "HIGH",
     "keepass2john <file> > k.hash; hashcat -m 13400 k.hash rockyou.txt"),
    (b"\x03\xD9\xA2\x9A\x65\xFB\x4B\xB5",
     "KeePass KDBX v1 database",
     "HIGH",
     "keepass2john <file> > k.hash; hashcat -m 13400 k.hash rockyou.txt  (mode 13400 for v1 too)"),
    (b"\x30\x82", "PFX/PKCS12 ASN.1 SEQUENCE (possible .pfx/.p12)",
     "HIGH",
     "openssl pkcs12 -info -in <file> -nodes  -or-  pfx2john <file> > p.hash; hashcat -m 24410 p.hash rockyou.txt"),
    (b"\x76\xff\xff\xff", "Kerberos .kirbi ticket (KRB-CRED ASN.1)",
     "HIGH",
     "ticketConverter.py <file> ticket.ccache; export KRB5CCNAME=ticket.ccache; klist"),
    (b"\x05\x04\x00\x10",  # MIT ccache v4 magic (0504 0010 in big-endian for some impls)
     "MIT Kerberos ccache (likely)",
     "HIGH",
     "export KRB5CCNAME=<file>; klist; nxc smb <dc> --use-kcache  (PtT)"),
    (b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
     "PGP private key block",
     "HIGH",
     "gpg --import <file>; gpg2john <file> > p.hash; hashcat -m 17010 p.hash rockyou.txt"),
    (b"-----BEGIN OPENSSH PRIVATE KEY-----",
     "OpenSSH private key (new format)",
     "HIGH",
     "ssh2john <file> > s.hash; hashcat -m 22921 s.hash rockyou.txt  (if encrypted)"),
    (b"-----BEGIN RSA PRIVATE KEY-----",
     "PEM RSA private key",
     "HIGH",
     "openssl rsa -in <file>  (if 'ENCRYPTED' header present -> ssh2john + hashcat)"),
    (b"PuTTY-User-Key-File-2:", "PuTTY private key v2 (.ppk)",
     "HIGH",
     "puttygen <file> -O private-openssh -o id_rsa; ssh -i id_rsa"),
    (b"PuTTY-User-Key-File-3:", "PuTTY private key v3 (Argon2 if encrypted)",
     "HIGH",
     "puttygen <file> -O private-openssh -o id_rsa; if encrypted: putty2john (jumbo) | hashcat"),
    # ESEDB / NTDS.dit:
    (b"\xef\xcd\xab\x89",   # ESEDB magic (NTDS.dit, ntds.dit, esent DB)
     "ESEDB (NTDS.dit / WID / SCCM site DB)",
     "CRITICAL",
     "impacket-secretsdump -ntds <file> -system SYSTEM LOCAL  (need matching SYSTEM hive)"),
    # MS-CFB (.msi, .doc, .vbk) — too generic to flag as loot directly
    # PKZIP - not flagged here; password-protected zip is handled by name.
    # LSASS minidump:
    (b"MDMP", "LSASS-shape minidump (.dmp)",
     "CRITICAL",
     "pypykatz lsa minidump <file>   -or-   mimikatz: sekurlsa::minidump <file>; sekurlsa::logonpasswords"),
    # SQLite (Firefox cookies, Chrome Login Data, KeePass keyfiles in disguise):
    (b"SQLite format 3\x00",
     "SQLite database (browser stores / app DBs)",
     "INFO",
     "sqlite3 <file> .tables; for Chrome Login Data / Firefox logins.json: firepwd.py / firefox_decrypt.py"),
    # Sysmon / event log .evtx
    (b"ElfFile\x00", "Windows event log (.evtx)",
     "INFO",
     "evtx_dump.py <file> | grep -iE 'EventID|user|target|process'; chainsaw hunt"),
]


def scan_magic(path, report, store=None):
    """Public entrypoint: scan a SINGLE file for known binary loot magic.
    Safe to call on any file, binary or text. Cheap (reads <=256 bytes).
    Use this from the main scan loop on every raw target (not just text)."""
    return _binary_magic_scan(path, report, store)


def _binary_magic_scan(path, report, store):
    """Read the first ~256 bytes; if magic matches a known cred/ticket/keystore
    format, emit a HIGH/CRITICAL finding with a concrete next-step command."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(256)
    except OSError:
        return 0
    if not head:
        return 0
    for magic, klass, sev, hint in _BINARY_MAGIC:
        if head.startswith(magic):
            report.add(sev, "INTERESTING FILES", path, None,
                       f"binary magic: {klass}", hint)
            return 1
    return 0
