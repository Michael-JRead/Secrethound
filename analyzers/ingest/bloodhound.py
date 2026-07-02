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
    # iter-37: DCSync rights - the operator's principal can pull ALL
    # domain password hashes without being admin. GetChanges is normal
    # DS replication, GetChangesAll adds encrypted-attribute (password
    # hash) replication - both are needed.
    "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
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
        # iter-24: pull domain from FQDN tail / Properties.domain for the
        # Store.dominant_domain() helper (drops <DOMAIN> in chain hints).
        dom = (p.get("domain") or "").strip().lower()
        if not dom and "@" in name:
            dom = name.split("@", 1)[1].strip().lower()
        elif not dom and "." in name:
            dom = name.split(".", 1)[1].strip().lower()
        # iter-38: capture the ObjectIdentifier (S-1-5-21-a-b-c-RID) so
        # Store.domain_sid() can extract the domain SID prefix.
        oid = (obj.get("ObjectIdentifier") or obj.get("objectidentifier")
               or "")

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
            # iter-47: constrained delegation - AllowedToDelegate is an
            # array of SPN strings for msDS-AllowedToDelegateTo. Fires
            # R-CONSTRAINED when operator owns this principal.
            atd = p.get("allowedtodelegate") or obj.get("AllowedToDelegate")
            if atd and isinstance(atd, list) and atd:
                facts.append("has_delegation_to")
                # store the SPN list in a dedicated Evidence with meta
                store.add(Evidence(kind="ldap_attr", user=short, source=src,
                                   meta={"allowed_to_delegate": [str(x) for x in atd]}))
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
                store.add(Evidence(kind="user", user=short, fact=f,
                                   domain=dom, source=src,
                                   meta={"object_identifier": oid} if oid else {}))
                n += 1
            if not facts:
                store.add(Evidence(kind="user", user=short, domain=dom, source=src,
                                   meta={"object_identifier": oid} if oid else {}))
            # iter-70: thread real domain into RECON hint so operator gets
            # a paste-ready 'htb.local/<u>:<p>' instead of '<DOM>/<u>:<p>'.
            _dom_lbl = dom or "<DOM>"
            if "kerberoastable" in facts:
                report.add("HIGH", "RECON", src, None,
                           f"kerberoastable: {short}",
                           f"impacket-GetUserSPNs -request-user '{short}' "
                           f"{_dom_lbl}/<u>:<p> -dc-ip <DC> -> hashcat -m 13100")
            if "asreproastable" in facts:
                report.add("HIGH", "RECON", src, None,
                           f"AS-REP-roastable: {short}",
                           f"impacket-GetNPUsers {_dom_lbl}/ -usersfile users.txt "
                           f"-no-pass -request -format hashcat -> hashcat -m 18200")
        elif kind_hint == "computers":
            if p.get("unconstraineddelegation"):
                store.add(Evidence(kind="host", host=name, fact="unconstrained", source=src))
                n += 1
            store.learn_host(names=[name])
            # iter-83: scan computer object description/info for inline creds
            # too - some HTB boxes drop local-admin creds in a computer's
            # 'info' field ("Ryan Bertrand's account: temppass2020"). Use the
            # same _scan_desc_for_pw helper as user objects. Computer 'short'
            # from _ingest_objects is the FQDN (no '@' to split on); strip
            # the domain suffix so the emitted netexec hint uses the samAcct
            # form 'WORKSTATION01' rather than 'WORKSTATION01.HTB.LOCAL'.
            _comp_short = short.split(".")[0] if "." in short else short
            for k in ("description", "info", "comment"):
                v = p.get(k)
                if not v:
                    continue
                if isinstance(v, list):
                    v = " ".join(str(x) for x in v if x)
                v = str(v)
                if _scan_desc_for_pw(v, _comp_short, store, report, src):
                    n += 1
        elif kind_hint == "groups":
            # iter-46: parse tier-0 groups (Domain Admins / Enterprise Admins
            # / Schema Admins / Backup Operators / Account Operators / Server
            # Operators / etc.) and mark their Members as admincount so
            # R-ADMIN-CRED fires even when the user's individual admincount
            # attribute wasn't set.
            g_short = short.lower()
            _PRIV = {"domain admins", "enterprise admins", "schema admins",
                     "backup operators", "account operators",
                     "server operators", "print operators", "administrators",
                     "domain controllers", "read-only domain controllers",
                     "protected users", "key admins", "enterprise key admins"}
            if g_short in _PRIV or p.get("admincount"):
                members = obj.get("Members") or obj.get("members") or []
                for mm in members:
                    if not isinstance(mm, dict):
                        continue
                    m_sid = (mm.get("ObjectIdentifier")
                             or mm.get("objectidentifier") or "")
                    m_type = (mm.get("ObjectType")
                              or mm.get("objecttype") or "").lower()
                    if m_type != "user" or not m_sid:
                        continue
                    store.add(Evidence(
                        kind="user", user=m_sid, fact="admincount",
                        domain=dom, source=src,
                        meta={"object_identifier": m_sid,
                              "via_group": g_short}))
                    n += 1
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
                # iter-70: thread real domain from the certtemplate object
                # (or Store) so the hint's UPN slot resolves. dom is set
                # above from p.get('domain') / name FQDN split.
                _esc_dom = dom or store.dominant_domain() or "<dom>"
                for esc in esc_list:
                    report.add("CRITICAL", "INTERESTING FILES", src, None,
                               f"AD CS {esc} candidate template: {short}",
                               f"certipy-ad req -u <u>@{_esc_dom} -p '<p>' -ca <CA> "
                               f"-template '{short}' -upn 'administrator@{_esc_dom}'")
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
