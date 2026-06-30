"""compliance.py - the SINGLE source of truth for OSCP/OSCP+ exam legality.

Every "next step" command the tool emits (playbook hints, correlation chains,
ingest suggestions) is linted against these sets. There must be exactly ONE
allowlist in the codebase - core/correlate.py and analyzers/playbook.py import
from here, they do NOT define their own (this prevents the lists drifting and a
prohibited tool slipping into a local copy).

Basis: OffSec OSCP / OSCP+ Exam Guide (PEN-200, Nov-2024+) as resolved by an
adversarial legality panel. Rulings:
  - ALLOWED  : manual enumeration, offline cracking, impacket, netexec, evil-winrm,
               certipy, gpp-decrypt, BloodHound collectors, pivoting (non-MSF).
  - LAB_ONLY : Responder/relay/poisoning - rely on SPOOFING, prohibited on exam.
               May be SHOWN only with an explicit [LAB-ONLY] tag, never as a top
               action.
  - DENIED   : sqlmap & automatic exploitation, mass vuln scanners, online
               brute-forcers (hydra), commercial frameworks, AI chatbots. NEVER
               emitted.
"""

LAB_ONLY_TAG = "[LAB-ONLY]"

# binaries the next-step engine MAY suggest freely (green)
ALLOWLIST_BINARIES = frozenset({
    # offline cracking (acquisition by poisoning is what's banned, not cracking)
    "hashcat", "john", "unshadow", "ssh2john", "keepass2john", "ansible2john",
    "pwsafe2john", "gpg2john", "keystore2john", "zip2john", "office2john",
    "pdf2john", "hashid", "hash-identifier", "nth", "name-that-hash",
    # credential validation / lateral movement (manual, targeted, creds in hand)
    "netexec", "nxc", "crackmapexec", "evil-winrm", "ssh", "sshpass", "scp",
    "mysql", "psql", "mssqlclient.py", "impacket-mssqlclient", "xfreerdp",
    "rdesktop", "smbclient", "smbmap", "ftp",
    # impacket suite (manual) - relay is NOT here (it's LAB_ONLY)
    "impacket-secretsdump", "secretsdump.py", "impacket-GetUserSPNs",
    "GetUserSPNs.py", "impacket-GetNPUsers", "GetNPUsers.py", "impacket-psexec",
    "psexec.py", "impacket-wmiexec", "wmiexec.py", "impacket-smbexec",
    "impacket-atexec", "impacket-dcomexec", "impacket-ticketConverter",
    "ticketConverter.py", "impacket-getTGT", "getTGT.py", "impacket-rpcdump",
    "klist", "kinit",
    # iter-23: ACL-edge / shadow-cred / RBCD chain tooling. All manual,
    # operator-driven, OSCP-legal (no spoofing, no auto-exploit).
    # NB: _primary_binaries() lowercases before lookup -> entries MUST be
    # lowercase or the allowlist miss falls through to "not on allowlist".
    "impacket-rbcd", "rbcd.py", "impacket-addcomputer", "addcomputer.py",
    "impacket-getst", "getst.py", "impacket-net", "net.py",
    "impacket-dacledit", "dacledit.py", "impacket-owneredit", "owneredit.py",
    "impacket-changepasswd", "changepasswd.py", "impacket-gmsadumper",
    "gmsadumper.py", "impacket-dpapi", "dpapi.py", "impacket-getpac",
    "getpac.py", "impacket-finddelegation", "finddelegation.py",
    "impacket-lookupsid", "lookupsid.py", "impacket-machine_role",
    # samba 'net' tool for net rpc password (ForceChangePassword path)
    "net",
    # AD enumeration / abuse (manual)
    "certipy", "certipy-ad", "gpp-decrypt", "ldapsearch", "windapsearch",
    "windapsearch.py", "bloodhound-python", "bloodhound.py", "SharpHound.exe",
    "kerbrute", "bloodyAD", "rpcclient", "tdbdump", "ldapdomaindump",
    "enum4linux", "enum4linux-ng", "snmpwalk", "snmp-check", "onesixtyone",
    "showmount", "dig", "dnsrecon", "nslookup", "host",
    # web enumeration / content discovery (no sqlmap, no nuclei)
    "gobuster", "ffuf", "feroxbuster", "dirb", "dirsearch", "wfuzz", "nikto",
    "whatweb", "wpscan", "curl", "wget",
    # recon
    "nmap", "masscan", "rustscan",
    # local privesc enumeration (checks only, no auto-exploit)
    "linpeas", "linpeas.sh", "winpeas", "winpeas.exe", "winPEASx64.exe",
    "linenum", "linux-exploit-suggester", "linux-exploit-suggester.sh", "les.sh",
    "powerup", "seatbelt", "pspy", "pspy64",
    # pivoting / tunnelling (only restriction is "not via Metasploit")
    "chisel", "ligolo-ng", "ligolo", "sshuttle", "plink", "socat", "proxychains",
    # local transforms / loot handling
    "openssl", "puttygen", "keytool", "gpg", "mdb-tools", "vncpwd",
    "firefox_decrypt", "firefox_decrypt.py", "roadrecon", "az", "gcloud",
    "kubectl", "aws", "base64", "ansible-vault", "ant", "7z", "unzip",
    # payload generation + listener (verbatim exempt - unlimited, all targets)
    "msfvenom", "msf-pattern_create", "pattern_create.rb", "pattern_offset.rb",
    # benign shell builtins/utils used inside multi-step hints
    "chmod", "echo", "cat", "cut", "export", "cd", "grep", "strings", "file",
    "head", "tail", "sort", "uniq", "tr", "awk", "sed", "python3", "for",
})

# may be SHOWN only with the [LAB-ONLY] tag; never a top/green action (spoofing)
LAB_ONLY_BINARIES = frozenset({
    "responder", "responder.py", "ntlmrelayx.py", "impacket-ntlmrelayx",
    "mitm6", "inveigh", "inveigh.ps1", "bettercap", "ettercap", "arpspoof",
    "dnsspoof", "tcpdump-poison",
})

# NEVER emitted under any circumstance.
# iter-16: drift audit added the online brute-forcers (hydra, medusa, ncrack,
# patator), spoofing primitives (responder, ntlmrelayx, mitm6, inveigh),
# online cracking services (crack.sh), and msfvenom (counts toward the
# OSCP+ 1-target Metasploit quota even when run locally).
DENYLIST_BINARIES = frozenset({
    "sqlmap", "sqlninja", "db_autopwn", "browser_autopwn", "autosploit",
    "nessus", "openvas", "gvm", "nexpose", "nexpose-client", "saint",
    "nuclei", "legion", "autorecon", "nmapautomator", "nmapautomator.sh",
    "canvas", "core-impact", "cobaltstrike", "armitage", "msfconsole",
    "msfpro", "burpsuite-pro", "chatgpt", "kai", "gemini", "copilot", "deepseek",
    # online brute-forcers (iter-16 audit)
    "hydra", "medusa", "ncrack", "patator", "crowbar", "thc-hydra",
    # spoofing primitives (iter-16 audit)
    "responder", "ntlmrelayx", "impacket-ntlmrelayx", "mitm6", "inveigh",
    "inveigh.ps1", "smbrelay", "smbrelayx", "impacket-smbrelayx", "ettercap",
    # public online cracking / submission services (iter-16 audit)
    "crack.sh", "hashes.com", "weakpass.com", "online-hash-crack",
    # msfvenom: payload generation counts toward MSF budget per OSCP+ rules
    "msfvenom",
})

import re as _re

_GLUE = {"&&", "||", ";", "|", "then", "on", "or", "#", "(", ")", "//", "->",
         "OR", "now:", "now", "first", "next"}


def _primary_binaries(cmd):
    """yield the leading binary of each shell-separated segment."""
    cmd = cmd.split("#", 1)[0]            # strip trailing annotation comment
    for seg in _re.split(r'[;|]|&&|\|\|', cmd):
        for t in seg.strip().split():
            t = t.strip("`'\"")
            if not t or t in _GLUE or t.startswith(("-", "<", "[", "(", "$", "/", "~", ".")):
                continue
            if "=" in t and "/" not in t and not t.endswith(".py"):
                continue  # env assignment like KRB5CCNAME=foo
            yield t.lower()
            break


def _all_tokens(cmd):
    return set(_re.split(r'[\s/;|]+', cmd.lower()))


def is_denied(cmd):
    """True if a categorically-prohibited tool appears anywhere."""
    if _all_tokens(cmd) & DENYLIST_BINARIES:
        return True
    return any(b in DENYLIST_BINARIES for b in _primary_binaries(cmd))


def needs_lab_tag(cmd):
    """True if a spoofing/relay tool appears (must be [LAB-ONLY]-tagged)."""
    if _all_tokens(cmd) & LAB_ONLY_BINARIES:
        return True
    return any(b in LAB_ONLY_BINARIES for b in _primary_binaries(cmd))


def lint_command(cmd, tagged=False):
    """Return (ok, reason). Strict positive allowlist: the primary binary of
    every segment must be explicitly allowed (or a tagged lab-only tool).
    Anything unrecognised is flagged so it can't slip through silently."""
    if not cmd or not cmd.strip():
        return True, ""
    if is_denied(cmd):
        return False, "references a PROHIBITED tool (denylist)"
    if needs_lab_tag(cmd) and not tagged:
        return False, f"references a spoofing/relay tool without a {LAB_ONLY_TAG} tag"
    for b in _primary_binaries(cmd):
        if b in ALLOWLIST_BINARIES or b in LAB_ONLY_BINARIES:
            continue
        # tolerate angle-bracket placeholders / pure paths the engine fills in
        if b.startswith(("<", "/", "./", "$", "~")) or b in _GLUE:
            continue
        return False, f"primary binary {b!r} is not on the OSCP allowlist"
    return True, ""


def assert_legal(commands_with_tags):
    """commands_with_tags: iterable of (cmd, tagged_bool). Raises AssertionError
    on the first non-compliant command - a hard build-time gate."""
    for cmd, tagged in commands_with_tags:
        ok, reason = lint_command(cmd, tagged)
        assert ok, f"OSCP-compliance violation: {reason}: {cmd!r}"
