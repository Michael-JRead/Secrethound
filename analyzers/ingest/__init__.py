"""ingest - parse the OUTPUT of other recon tools the user already ran.

Reading files the operator already produced on their OWN box is passive and
OSCP-exam-legal (no traffic, no scanning). Each adapter is a pure function
`parse(path, store, report) -> int` plus a `detect(path, head) -> bool` sniffer.
Dispatch is content-sniff first (loot arrives with arbitrary names), one adapter
per file.
"""
import os

from analyzers.ingest.evidence import Evidence, Store
from analyzers.ingest import (ext_secretsdump, ext_nmap, netexec_db, bloodhound,
                              ldapdomaindump, enum4linux, webdirs, potfile,
                              certipy)

# order matters: most specific sniffers first
# iter-15: register potfile so in-tree john.pot / hashcat.potfile / *.potfile
# files are loaded into _POT_INDEX during the ingest pass (previously the
# detect()/parse() pair was dead code - never reached the dispatcher).
# iter-23: certipy goes BEFORE bloodhound because certipy_find.json can sniff
# as bloodhound JSON (both have AD-shaped top-level keys); certipy.detect()
# requires both 'Certificate Authorities' + 'Certificate Templates'.
ADAPTERS = [ext_secretsdump, ext_nmap, netexec_db, certipy, bloodhound,
            ldapdomaindump, enum4linux, webdirs, potfile]


def _head(path, n=4096):
    with open(path, "rb") as fh:
        return fh.read(n).decode("utf-8", "replace")


def run(targets, report, store, args=None):
    """parse every target with the first adapter that claims it.
    Returns the set of absolute paths claimed (so files.analyze_tree can skip)."""
    claimed = set()
    for path in targets:
        try:
            head = _head(path)
        except OSError:
            continue
        for mod in ADAPTERS:
            try:
                if mod.detect(path, head):
                    mod.parse(path, store, report)
                    claimed.add(os.path.abspath(path))
                    break
            except Exception:
                continue
    return claimed
