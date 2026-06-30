"""ldapdomaindump.py - parse ldapdomaindump domain_*.json.

The description/info attribute frequently holds a plaintext password (a classic
OSCP AD finding). UAC bits reveal AS-REP-able / unconstrained / no-password-req
accounts.
"""
import os
import json
from analyzers import filters
from analyzers.ingest.evidence import Evidence

# userAccountControl bits
_DONT_REQ_PREAUTH = 0x400000
_TRUSTED_FOR_DELEG = 0x80000
_PASSWD_NOTREQD = 0x20
_PWD_PASSWORD_HINT = ("pass", "pwd", "cred", "default")


def detect(path, head):
    name = os.path.basename(path).lower()
    if name.startswith("domain_") and name.endswith(".json"):
        return True
    h = head[:400].lower()
    return '"attributes"' in h and ('"dn"' in h or '"samaccountname"' in h)


def _first(attrs, key):
    v = attrs.get(key)
    if isinstance(v, list):
        return str(v[0]) if v else ""
    return str(v) if v is not None else ""


def parse(path, store, report):
    try:
        with open(path, "r", errors="ignore") as fh:
            doc = json.load(fh)
    except (ValueError, OSError):
        return 0
    if not isinstance(doc, list):
        doc = doc.get("data", doc) if isinstance(doc, dict) else []
    n = 0
    for obj in doc:
        if not isinstance(obj, dict):
            continue
        a = obj.get("attributes", obj)
        a = {k.lower(): v for k, v in a.items()} if isinstance(a, dict) else {}
        user = _first(a, "samaccountname")
        if not user:
            continue
        n += 1
        store.add(Evidence(kind="user", user=user, source=path))
        desc = (_first(a, "description") + " " + _first(a, "info")).strip()
        if desc:
            # iter-23: prefer 'password is X' marker over first-token-wins.
            # Shared with bloodhound.py via filters.extract_pw_from_desc().
            tok = filters.extract_pw_from_desc(desc)
            if tok and not filters.is_placeholder(tok) \
                    and not filters.is_code_not_literal(tok, desc):
                report.add("HIGH", "CRED PAIRS", path, None,
                           f"description hints cred for {user}: {desc[:80]}",
                           f"try: netexec smb <DC-IP> -u '{user}' -p '{tok}' -k")
                store.add(Evidence(kind="plaintext", user=user, plaintext=tok, source=path))
        try:
            uac = int(_first(a, "useraccountcontrol") or 0)
        except ValueError:
            uac = 0
        if uac & _DONT_REQ_PREAUTH:
            store.add(Evidence(kind="user", user=user, fact="asreproastable", source=path))
            report.add("HIGH", "RECON", path, None, f"AS-REP-roastable (UAC): {user}",
                       "impacket-GetNPUsers <DOM>/ -usersfile users.txt -no-pass -> hashcat -m 18200")
        if _first(a, "serviceprincipalname"):
            store.add(Evidence(kind="user", user=user, fact="kerberoastable", source=path))
        if uac & _TRUSTED_FOR_DELEG:
            store.add(Evidence(kind="user", user=user, fact="unconstrained", source=path))
    if n:
        report.add("INFO", "RECON", path, None, f"ldapdomaindump parsed: {n} users")
    return n
