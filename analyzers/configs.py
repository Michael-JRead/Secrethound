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
    """Decode an unattend <Value>. Returns (password, source) or None."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    try:
        text = raw.decode("utf-16-le")
    except Exception:
        return None
    if not text:
        return None
    suffix = parent_name or ""
    if suffix and text.endswith(suffix) and len(text) > len(suffix):
        return text[:-len(suffix)], "b64-utf16le, parent-suffix stripped"
    # third-party path: no suffix appended
    if text.isprintable():
        return text, "b64-utf16le, no suffix"
    return None


def _emit_password(report, store, path, parent, pw, note):
    if not pw or filters.is_placeholder(pw):
        return
    label = parent or "unattend password"
    detail = f"unattend {label}: {pw}  ({note})"
    report.add("CRITICAL", "CRED PAIRS", path, None, detail,
               hint=("Windows unattend password recovered - log in directly: "
                     f"netexec smb <DC-IP> -u Administrator -p '{pw}'"))
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
    try:
        with open(path, "r", errors="ignore") as fh:
            head = fh.read(2048)
    except OSError:
        return 0
    if not _UNATTEND_HINT.search(head):
        return 0
    return _walk_unattend(path, report, store)
