"""potfile.py - cross-reference found hashes against locally-cracked plaintext.

If a hash secrethound found ALSO appears in the operator's hashcat potfile or
john.pot, it is already CRACKED - surface the plaintext as a usable credential
(feeding the spray/auth chains) and drop it from the crack-ready list so it
isn't re-cracked. Reading your own potfile is passive and exam-legal.
"""
import os
import re
from analyzers import patterns, filters
from analyzers.ingest.evidence import Evidence

_POT_INDEX = {}          # normalised hash -> (plaintext, source-file)
_LOADED = set()

DEFAULT_POTS = [
    "~/.hashcat/hashcat.potfile",
    "~/.local/share/hashcat/hashcat.potfile",
    "~/.john/john.pot",
]
_DYNAMIC = re.compile(r'^\$(?:nt|lm|dynamic_\d+)\$', re.IGNORECASE)


def normalize(h):
    """join key: lowercase; strip john's $NT$/$LM$/$dynamic_N$ wrapper to bare
    hex so john's pot matches secrethound's bare NTLM. krb/NetNTLM keys (which
    legitimately contain ':' and '$') are kept whole-lowercased."""
    if not h:
        return ""
    s = h.strip().lower()
    m = _DYNAMIC.match(s)
    if m:
        rest = s[m.end():]
        # $dynamic_N$<hex>  or  $NT$<hex>
        return rest if rest else s
    return s


def load_pot(path):
    p = os.path.abspath(os.path.expanduser(path))
    if p in _LOADED:
        return 0
    _LOADED.add(p)
    n = 0
    try:
        with open(p, "r", errors="ignore") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line or ":" not in line:
                    continue
                key, _, plain = line.rpartition(":")
                if not key or not plain:
                    continue
                _POT_INDEX[normalize(key)] = (plain, p)
                n += 1
    except OSError:
        pass
    return n


# ── adapter interface: a potfile found inside the scanned tree ──
def detect(path, head):
    name = os.path.basename(path).lower()
    if name.endswith(".potfile") or name == "john.pot" or name == "hashcat.potfile":
        return True
    # heuristic: many 'hash:plaintext' lines
    return False


def parse(path, store, report):
    return load_pot(path)


# ── the cross-reference pass (run after scanning) ──
def correlate(report, store, args=None):
    # load default + user-specified potfiles
    if not (args and getattr(args, "no_pot", False)):
        for p in DEFAULT_POTS:
            load_pot(p)
        for p in (getattr(args, "pot", None) or []):
            load_pot(p)
    if not _POT_INDEX:
        return store.cracked

    # cross-ref every collected hash (patterns.HASHES shape: mode,name,val,fp,ln)
    for mode, name, val, fp, ln in list(patterns.HASHES):
        if filters.is_blank_hash(val):
            continue
        hit = _POT_INDEX.get(normalize(val))
        if not hit:
            continue
        plain, potsrc = hit
        store.cracked.add(normalize(val))
        is_ntlm = "ntlm" in name.lower() or mode == "1000"
        pth = f"   (or PtH: netexec smb <DC-IP> -u '<user>' -H {val})" if is_ntlm else ""
        report.add("CRITICAL", "CRED PAIRS", fp, ln,
                   f"CRACKED {name}: {val[:24]}… = {plain!r}",
                   f"hash cracked in {os.path.basename(potsrc)} → use it: "
                   f"netexec smb <DC-IP> -u '<user>' -p '{plain}' -k{pth}")
        store.add(Evidence(kind="plaintext", plaintext=plain, hash=val,
                           hash_mode=mode, source=fp, line=ln))
    return store.cracked
