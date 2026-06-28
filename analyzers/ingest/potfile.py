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
                # iter-14: hashcat/john pot rows always have the HASH on the
                # left and plaintext on the right, split by the FIRST ":"
                # when the hash itself is a single token. For NTLM-pair
                # / krb5tgs / known-prefix hashes, the hash carries ':' so
                # we need a prefix-aware split. Heuristic: if the line
                # starts with a recognised hash-prefix shape, find the
                # delimiter after the hash blob; otherwise split on the
                # rightmost colon (legacy behaviour).
                key, plain = _split_pot_line(line)
                if not key or not plain:
                    continue
                # iter-14: track ALL plaintexts seen for a hash (collisions
                # mean two pot files; first-loaded wins, but record alt).
                norm = normalize(key)
                existing = _POT_INDEX.get(norm)
                if existing is None:
                    _POT_INDEX[norm] = (plain, p)
                elif existing[0] != plain:
                    # second potfile disagrees - keep first-loaded but
                    # record so the operator can see it.
                    _POT_COLLISIONS.setdefault(norm, [existing]).append((plain, p))
                n += 1
    except OSError:
        pass
    return n


def _split_pot_line(line):
    """Split a 'hash:plain' pot line, prefix-aware so $krb5tgs$.../NTLM-pair
    hashes don't get clobbered by rpartition."""
    # NTLM pair: 32hex:32hex:plain   -> hash = '32hex:32hex'
    import re as _re
    m = _re.match(r'^([a-fA-F0-9]{32}:[a-fA-F0-9]{32}):(.*)$', line)
    if m:
        return m.group(1), m.group(2)
    # known $-prefix hashes carry their own internal colons; split AFTER the
    # last segment of the hash token.
    if line.startswith("$"):
        # split on the FIRST ': ' (with space) if present, else fall back
        # to splitting on the colon that doesn't immediately follow a digit.
        if ": " in line:
            k, _, p = line.partition(": ")
            return k, p
    # default: rightmost ':' wins
    key, _, plain = line.rpartition(":")
    return key, plain


# iter-14: track potfile collisions for operator visibility
_POT_COLLISIONS = {}


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
    # iter-15: invert load order so --pot args win over defaults. The
    # collision-handling in _load_pot keeps the FIRST plaintext seen for
    # each hash, so loading CLI-args first means the operator's explicit
    # potfile takes precedence over ~/.hashcat / ~/.john.
    if not (args and getattr(args, "no_pot", False)):
        for p in (getattr(args, "pot", None) or []):
            load_pot(p)
        for p in DEFAULT_POTS:
            load_pot(p)
    if not _POT_INDEX:
        return store.cracked

    # iter-15: surface cross-potfile collisions so the operator knows when
    # two potfiles disagree about the plaintext for the same hash.
    for h, alts in _POT_COLLISIONS.items():
        if not alts:
            continue
        winning = _POT_INDEX.get(h)
        if not winning:
            continue
        wp, wsrc = winning
        others = ", ".join(f"{p!r} (from {os.path.basename(s)})" for p, s in alts)
        report.add("INFO", "RECON", wsrc, None,
                   f"potfile collision for hash {h[:16]}...: kept {wp!r}; alt={others}",
                   hint="two potfiles disagree on this hash's plaintext; verify by hand")

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
