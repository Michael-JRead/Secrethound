"""bloodhound.py - parse BloodHound (legacy + CE) JSON/zip into AD facts.

Surfaces kerberoastable / AS-REP-able / admincount / unconstrained users +
computers so the correlator can suggest the exam-legal roast/PtH chains.

iter-23 (corpus mine wwzwk72m3 gaps):
  - extract ACL edges (Aces[].RightName) so correlator can route generic write
    / AddKeyCredentialLink / WriteDacl / ForceChangePassword chains
  - extract cleartext-password tokens from Properties.description / info /
    userPassword / unixUserPassword / cascadeLegacyPwd (HTB Forest pattern)
  - extend _TYPES to BloodHound CE post-2023 collections (containers,
    certtemplates, cas, azure*).
"""
import os
import json
import zipfile
from analyzers import filters
from analyzers.ingest.evidence import Evidence

# iter-23: extend with BloodHound CE post-2023 collection names so newer
# SharpHound zips parse fully. Legacy keys first, CE-only last - dispatch
# keys off _TYPES for the JSON-naming sniff in detect() too.
_TYPES = ("users", "computers", "groups", "domains", "gpos", "ous",
          "containers", "certtemplates", "cas", "issuancepolicies",
          "azureapplications", "azureusers", "azuregroups", "azuretenants")

# Abusable ACL rights that map to a concrete OSCP-legal escalation primitive.
# RightName values come straight from SharpHound; the operator's actual
# escalation depends on principal type (user/computer/group), so we tag the
# edge and let correlate.py route it.
_ACL_RIGHTS = frozenset({
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
    "ForceChangePassword", "AddMember", "AddKeyCredentialLink",
    "ReadGMSAPassword", "ReadLAPSPassword", "AllExtendedRights",
    "AddSelf", "WriteSPN", "Owns", "WriteAccountRestrictions",
    "AddAllowedToAct",
})

# Description-field keys that historically carry plaintext passwords on AD
# (the HTB Forest 'svc-alfresco' pattern). userPassword in particular is a
# real password attribute (not just description) and any value there is
# automatically interesting.
_PWD_ATTR_KEYS = ("description", "info", "userpassword", "unixuserpassword",
                  "cascadelegacypwd", "comment")
_PWD_PASSWORD_HINT = ("pass", "pwd", "cred", "default", "secret", "login")


def detect(path, head):
    name = os.path.basename(path).lower()
    if name.endswith(".zip") and "bloodhound" in name:
        return True
    if name.endswith(".json"):
        if any(name.endswith(f"_{t}.json") or name == f"{t}.json" for t in _TYPES):
            return True
        h = head[:400].lower()
        if '"meta"' in h and '"type"' in h and any(f'"{t}"' in h for t in _TYPES):
            return True
    return False


def _props(obj):
    p = obj.get("Properties") or obj.get("properties") or {}
    return {k.lower(): v for k, v in p.items()}


def _scan_desc_for_pw(text, user, store, report, src):
    """Extract a candidate password from a description-ish field. Uses the
    shared filters.extract_pw_from_desc() so 'password is s3rvice' beats
    the first-token-wins bug (HTB Forest pattern). Emits at most one
    credential per field to stay quiet on prose."""
    tok = filters.extract_pw_from_desc(text or "")
    if not tok:
        return False
    if filters.is_placeholder(tok) or filters.is_code_not_literal(tok, text or ""):
        return False
    report.add("HIGH", "CRED PAIRS", src, None,
               f"BloodHound desc hints cred for {user}: {(text or '')[:80]}",
               f"try: netexec smb <DC-IP> -u '{user}' -p '{tok}' -k")
    store.add(Evidence(kind="plaintext", user=user, plaintext=tok, source=src))
    return True


def _scan_user_password_attr(text, user, store, report, src):
    """userPassword is a real LDAP attribute - any non-placeholder value is
    a direct credential, not a description hint. No 'pwd' keyword gate."""
    text = (text or "").strip()
    if not text:
        return False
    # value can be base64'd ({CRYPT}..., {SHA}..., {SSHA}...) or plain
    if text.lower().startswith(("{crypt}", "{sha}", "{ssha}", "{md5}", "{smd5}")):
        report.add("HIGH", "PASSWORD HASHES", src, None,
                   f"LDAP userPassword hash for {user}: {text}",
                   "extract scheme prefix, choose hashcat mode (e.g. SSHA = -m 111)")
        return True
    if 4 <= len(text) <= 80 and not filters.is_placeholder(text) \
            and not filters.is_code_not_literal(text, text):
        report.add("HIGH", "CRED PAIRS", src, None,
                   f"LDAP userPassword for {user}: {text}",
                   f"try: netexec smb <DC-IP> -u '{user}' -p '{text}' -k")
        store.add(Evidence(kind="plaintext", user=user, plaintext=text, source=src))
        return True
    return False


def _ingest_aces(obj, principal_name, target_kind, store, src):
    """iter-23: emit one Evidence(kind='acl_edge') per abusable RightName.
    target_kind is 'users'/'computers'/'groups'/etc - tells correlate.py
    how to route (e.g. RBCD vs ForceChangePassword for GenericWrite).
    Computer objects in BloodHound use FQDN in Properties.name, NOT the
    samaccountname '$' suffix, so passing the kind via meta is more
    reliable than parsing the target string."""
    aces = obj.get("Aces") or obj.get("aces") or []
    if not isinstance(aces, list):
        return 0
    target = principal_name.split("@")[0]
    n = 0
    for ace in aces:
        if not isinstance(ace, dict):
            continue
        right = ace.get("RightName") or ace.get("rightname") or ""
        if right not in _ACL_RIGHTS:
            continue
        psid = ace.get("PrincipalSID") or ace.get("principalsid") or ""
        ptype = ace.get("PrincipalType") or ace.get("principaltype") or ""
        # SharpHound doesn't expose the principal NAME directly in the Aces
        # array - it's a SID-only reference. Operator runs `bloodhound-python`
        # or the GUI to resolve; we still emit the SID so the route is wired.
        store.add(Evidence(
            kind="acl_edge",
            user=psid,                 # principal (will be resolved by op)
            fact=right,
            host=target,
            source=src,
            meta={"principal_sid": psid,
                  "principal_type": ptype,
                  "target": target,
                  "target_kind": target_kind}))
        n += 1
    return n


def _ingest_objects(data, kind_hint, store, report, src):
    n = 0
    for obj in data:
        if not isinstance(obj, dict):
            continue
        p = _props(obj)
        name = (p.get("name") or p.get("samaccountname") or
                p.get("displayname") or "").strip()
        if not name:
            continue
        short = name.split("@")[0]

        # iter-23: ACL edges fire on EVERY object that has Aces (users,
        # computers, groups, domains, gpos, ous, certtemplates). Run before
        # the per-kind specifics so even non-user objects contribute.
        n += _ingest_aces(obj, name, kind_hint, store, src)

        if kind_hint == "users":
            facts = []
            if p.get("hasspn"):
                facts.append("kerberoastable")
            if p.get("dontreqpreauth"):
                facts.append("asreproastable")
            if p.get("admincount"):
                facts.append("admincount")
            if p.get("unconstraineddelegation"):
                facts.append("unconstrained")
            # iter-23: extract password tokens from description/info/etc.
            # The HTB Forest box's `svc-alfresco` password lives in
            # Properties.info; ldapdomaindump-style scanning catches it.
            for k in _PWD_ATTR_KEYS:
                v = p.get(k)
                if not v:
                    continue
                if isinstance(v, list):
                    v = " ".join(str(x) for x in v if x)
                v = str(v)
                if k == "userpassword":
                    _scan_user_password_attr(v, short, store, report, src)
                else:
                    if _scan_desc_for_pw(v, short, store, report, src):
                        pass
                # always keep the raw attribute on the user for downstream
                store.add(Evidence(kind="ldap_attr", user=short, source=src,
                                   meta={k: v}))
            for f in facts:
                store.add(Evidence(kind="user", user=short, fact=f, source=src))
                n += 1
            if not facts:
                store.add(Evidence(kind="user", user=short, source=src))
            if "kerberoastable" in facts:
                report.add("HIGH", "RECON", src, None,
                           f"kerberoastable: {short}",
                           f"impacket-GetUserSPNs -request-user '{short}' "
                           f"<DOM>/<u>:<p> -dc-ip <DC> -> hashcat -m 13100")
            if "asreproastable" in facts:
                report.add("HIGH", "RECON", src, None,
                           f"AS-REP-roastable: {short}",
                           f"impacket-GetNPUsers <DOM>/ -usersfile users.txt "
                           f"-no-pass -request -format hashcat -> hashcat -m 18200")
        elif kind_hint == "computers":
            if p.get("unconstraineddelegation"):
                store.add(Evidence(kind="host", host=name, fact="unconstrained", source=src))
                n += 1
            store.learn_host(names=[name])
        elif kind_hint == "certtemplates":
            # iter-23: BloodHound CE collects ADCS templates directly. Mirror
            # the certipy-find shape so correlate.py routes ESC chains.
            esc_list = []
            for k, _esc in (("enrolleesuppliessubject", "ESC1"),
                            ("requiresmanagerapproval", None),
                            ("nosecurityextension", "ESC9"),
                            ("schemaversion", None)):
                pass
            if p.get("enrolleesuppliessubject") and p.get("clientauthentication"):
                esc_list.append("ESC1")
            if p.get("nosecurityextension"):
                esc_list.append("ESC9")
            if esc_list:
                store.add(Evidence(kind="cert_template", source=src,
                                   meta={"template": short, "esc": esc_list}))
                for esc in esc_list:
                    report.add("CRITICAL", "INTERESTING FILES", src, None,
                               f"AD CS {esc} candidate template: {short}",
                               f"certipy-ad req -u <u>@<dom> -p '<p>' -ca <CA> "
                               f"-template '{short}' -upn 'administrator@<dom>'")
                    n += 1
    return n


def _load_json_blob(raw, store, report, src):
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        return 0
    if isinstance(doc, dict):
        t = (doc.get("meta", {}) or {}).get("type", "")
        data = doc.get("data", [])
        hint = t if t in _TYPES else ("users" if any("hasspn" in str(d).lower() for d in data[:5]) else "computers")
        return _ingest_objects(data, hint, store, report, src)
    if isinstance(doc, list):
        return _ingest_objects(doc, "users", store, report, src)
    return 0


def parse(path, store, report):
    if path.lower().endswith(".zip"):
        n = 0
        try:
            with zipfile.ZipFile(path) as z:
                for nm in z.namelist():
                    if not nm.lower().endswith(".json"):
                        continue
                    t = next((tt for tt in _TYPES if tt in nm.lower()), "users")
                    try:
                        n += _ingest_objects(json.loads(z.read(nm)).get("data", []), t, store, report, path)
                    except (ValueError, KeyError, zipfile.BadZipFile):
                        continue
        except (zipfile.BadZipFile, OSError):
            return 0
        return n
    try:
        with open(path, "r", errors="ignore") as fh:
            return _load_json_blob(fh.read(), store, report, path)
    except OSError:
        return 0
