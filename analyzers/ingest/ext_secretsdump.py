"""ext_secretsdump.py - parse impacket secretsdump / NTDS / SAM dumps.

The richest, most common AD loot artifact. Format is pwdump:
    DOMAIN\\user:RID:LMHASH:NTHASH:::
Each NT hash becomes a per-user Evidence record AND is pushed into
patterns.HASHES so it flows to --hashes, the potfile cross-ref, and the PtH
chains. Blank LM/NT are recognised and skipped (never crackable).
"""
import os
import re
from analyzers import patterns, filters, known_hashes
from analyzers.ingest.evidence import Evidence

# DOMAIN\user:RID:LM:NT:::   or   user:RID:LM:NT:::
_PWDUMP = re.compile(
    r'^(?P<who>[^\s:]+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::')
# kerberos key line:  user:aes256-cts-hmac-sha1-96:<hex>
_KRBKEY = re.compile(r'^(?P<who>[^\s:]+):(?P<etype>aes\d+-cts-hmac-sha1-96|des-cbc-md5):(?P<key>[a-f0-9]{16,})', re.IGNORECASE)
# cleartext:  user:CLEARTEXT:<password>
_CLEAR = re.compile(r'^(?P<who>[^\s:]+):CLEARTEXT:(?P<pw>.+)$')


def detect(path, head):
    for line in head.splitlines()[:200]:
        if _PWDUMP.match(line.strip()):
            return True
    return False


def _split_who(who):
    if "\\" in who:
        dom, _, user = who.partition("\\")
        return dom, user
    return "", who


def parse(path, store, report):
    n = 0
    try:
        with open(path, "r", errors="ignore") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                m = _PWDUMP.match(line)
                if m:
                    dom, user = _split_who(m.group("who"))
                    nt = m.group("nt").lower()
                    if filters.is_blank_hash(nt):
                        continue
                    n += 1
                    known = known_hashes.lookup(nt)
                    if known is not None:
                        report.add("CRITICAL", "CRED PAIRS", path, ln,
                                   f"{user} NT=DEFAULT '{known}' ({nt[:12]}...)",
                                   f"log in directly: netexec smb <DC-IP> -u '{user}' -p '{known}'")
                        store.add(Evidence(kind="plaintext", user=user, domain=dom,
                                           plaintext=known, hash=nt, source=path, line=ln))
                    else:
                        report.add("HIGH", "PASSWORD HASHES", path, ln,
                                   f"NTLM (NT) {user}: {nt}",
                                   f"PtH: netexec smb <DC-IP> -u '{user}' -H {nt}")
                        patterns.HASHES.append(("1000", "NTLM", nt, path, ln))
                    # iter-78: RID 500 is the built-in local Administrator on
                    # EVERY Windows host - only tier-0 when the source is a
                    # domain dump (NTDS.dit / DCSync output) where the RID 500
                    # is unambiguously the DOMAIN Administrator. A dumped local
                    # SAM has RID 500 too but it's just the local admin of
                    # that one workstation, and flagging it as admincount fires
                    # bogus R-ADMIN-CRED against the DC.
                    # Heuristic: dom (from DOMAIN\user) is set on domain dumps
                    # (NTDS pwdump rows), absent on local SAM dumps.
                    _is_domain_dump = bool(dom)
                    _rid500_da = m.group("rid") == "500" and _is_domain_dump
                    store.add(Evidence(kind="hash", user=user, domain=dom, hash=nt,
                                       hash_mode="1000", source=path, line=ln,
                                       fact="admincount" if _rid500_da else ""))
                    continue
                mc = _CLEAR.match(line)
                if mc:
                    dom, user = _split_who(mc.group("who"))
                    pw = mc.group("pw").strip()
                    if pw and not filters.is_placeholder(pw):
                        n += 1
                        report.add("CRITICAL", "CRED PAIRS", path, ln,
                                   f"CLEARTEXT {user}={pw}",
                                   f"reversible-encryption cred: netexec smb <DC-IP> -u '{user}' -p '{pw}'")
                        store.add(Evidence(kind="plaintext", user=user, domain=dom,
                                           plaintext=pw, source=path, line=ln))
    except OSError:
        return 0
    if n:
        report.add("INFO", "RECON", path, None,
                   f"secretsdump/NTDS dump parsed: {n} accounts")
    return n
