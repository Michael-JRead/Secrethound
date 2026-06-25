"""bloodhound.py - parse BloodHound (legacy + CE) JSON/zip into AD facts.

Surfaces kerberoastable / AS-REP-able / admincount / unconstrained users +
computers so the correlator can suggest the exam-legal roast/PtH chains.
"""
import os
import json
import zipfile
from analyzers.ingest.evidence import Evidence

_TYPES = ("users", "computers", "groups", "domains", "gpos", "ous")


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


def _ingest_objects(data, kind_hint, store, report, src):
    n = 0
    for obj in data:
        if not isinstance(obj, dict):
            continue
        p = _props(obj)
        name = (p.get("name") or p.get("samaccountname") or "").strip()
        if not name:
            continue
        short = name.split("@")[0]
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
            if p.get("description"):
                store.add(Evidence(kind="ldap_attr", user=short, source=src,
                                   meta={"description": p.get("description")}))
            for f in facts:
                store.add(Evidence(kind="user", user=short, fact=f, source=src))
                n += 1
            if not facts:
                store.add(Evidence(kind="user", user=short, source=src))
            if "kerberoastable" in facts:
                report.add("HIGH", "RECON", src, None,
                           f"kerberoastable: {short}",
                           "impacket-GetUserSPNs -request <DOM>/<u>:<p> -dc-ip <DC> -> hashcat -m 13100")
            if "asreproastable" in facts:
                report.add("HIGH", "RECON", src, None,
                           f"AS-REP-roastable: {short}",
                           "impacket-GetNPUsers <DOM>/ -usersfile users.txt -no-pass -> hashcat -m 18200")
        elif kind_hint == "computers":
            if p.get("unconstraineddelegation"):
                store.add(Evidence(kind="host", host=name, fact="unconstrained", source=src))
                n += 1
            store.learn_host(names=[name])
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
