"""Shared stubs, fixture constants and runners for the SecretHound test suite.

Pure stdlib, zero dependencies. Every helper is hermetic (tempfile fixtures,
no network, no subprocess) so the suite behaves identically on an exam Kali
box and in CI:

    python3 -m unittest discover -s tests -v

Import with `from tests._helpers import *` (or explicit names).
"""
import io
import os
import re
import sys
import shutil
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

# core.ui.UI honours NO_COLOR and auto-flips to ASCII on a non-UTF locale ->
# pin both so the rendering assertions hold on any box.
os.environ.pop("NO_COLOR", None)
os.environ["LANG"] = "C.UTF-8"
os.environ.pop("LC_ALL", None)
os.environ.pop("LC_CTYPE", None)

from analyzers import keyword, patterns, compliance, filters  # noqa: E402
from analyzers.ingest.evidence import Store, Evidence  # noqa: E402
from core import correlate  # noqa: E402

# verified: not blank, not a canonical cheat-sheet run, not in known_hashes
NT = "c4b0e1b10c7ce2c4a2e9d1b6f5a3d8e7"
BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"
SID = "S-1-5-21-1111-2222-3333-1105"
BH_SRC = "/loot/dc01/bloodhound/users.json"
# colour codes ONLY; "\033[K" (erase-to-EOL) is cursor control and is allowed
# under --no-color (the progress bar uses it on a tty stderr).
SGR = re.compile(r'\033\[[0-9;]*m')
# tools that must never be NAMED in a hint= string (hints are not linted by
# compliance.lint_command, so this tuple is the only guard).
BANNED_TOOLS = ("sqlmap", "hydra", "medusa", "ncrack", "patator", "responder",
                "ntlmrelayx", "mitm6", "inveigh", "nessus", "openvas")


class StubReport:
    """Minimal stand-in for core.report.Report (same add() signature)."""

    def __init__(self):
        self.findings = []
        self.root = "."

    def add(self, severity, category, path, lineno, detail, hint=None):
        self.findings.append({"severity": severity, "category": category, "file": path,
                              "line": lineno, "detail": detail, "hint": hint})

    def cat(self, category):
        return [f for f in self.findings if f["category"] == category]

    def grep(self, sub):
        return [f for f in self.findings if sub in f["detail"]]


def run_analyzer(mod, text, ext=".txt", name="fixture"):
    """Write `text` to <tmp>/<name><ext>, run mod.analyze(path, report, store).
    Returns (report, store). The tempdir is removed afterwards."""
    patterns.HASHES.clear()
    d = tempfile.mkdtemp(prefix="sh-test-")
    p = os.path.join(d, name + ext)
    with open(p, "w") as fh:
        fh.write(text)
    r, s = StubReport(), Store()
    try:
        mod.analyze(p, r, s)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return r, s


def run_keyword(text, ext=".txt", name="fixture"):
    return run_analyzer(keyword, text, ext, name)


def run_patterns(text, ext=".txt", name="fixture"):
    return run_analyzer(patterns, text, ext, name)


try:
    from analyzers import privesc as _privesc          # D3 deliverable
    HAVE_PRIVESC = True
except ImportError:                                     # pragma: no cover
    _privesc = None
    HAVE_PRIVESC = False


def run_privesc(text, ext=".txt", name="fixture"):
    """Run analyzers.privesc.analyze (if present) then keyword.analyze on the
    SAME file; findings/evidence are merged. Mirrors the per-file loop in
    secrethound.main() where privesc.analyze runs right after keyword."""
    patterns.HASHES.clear()
    d = tempfile.mkdtemp(prefix="sh-test-")
    p = os.path.join(d, name + ext)
    with open(p, "w") as fh:
        fh.write(text)
    r, s = StubReport(), Store()
    try:
        if _privesc is not None:
            _privesc.analyze(p, r, s)
        keyword.analyze(p, r, s)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return r, s


# ---- correlator builders (Evidence by hand - no file parsing) ----
def ad_store():
    s = Store()
    s.add(Evidence(kind="host", host="10.10.11.5", fact="dc", source="/loot/dc01/nmap.txt"))
    s.learn_host("10.10.11.5", ["dc01.corp.local"])
    s.add(Evidence(kind="user", user="jdoe", domain="corp.local", source=BH_SRC,
                   meta={"object_identifier": SID}))
    return s


def add_plaintext(s, user="jdoe", pw="Summer2024!"):
    s.add(Evidence(kind="plaintext", user=user, plaintext=pw, domain="corp.local",
                   source="/loot/dc01/notes.txt", line=3))


def add_nt(s, user="jdoe", nt=NT):
    s.add(Evidence(kind="hash", user=user, hash=nt, domain="corp.local",
                   source="/loot/dc01/secretsdump.txt", line=2))


def add_acl_edge(s, right, target="CORP.LOCAL", target_kind="domains"):
    s.add(Evidence(kind="acl_edge", user=SID, fact=right, host=target, source=BH_SRC, line=1,
                   meta={"principal_sid": SID, "principal_type": "User",
                         "target": target, "target_kind": target_kind}))


def add_cert_template(s, template, esc, lab_only=False, ca="corp-CA"):
    s.add(Evidence(kind="cert_template", source="/loot/dc01/certipy_find.json", line=1,
                   meta={"template": template, "ca": ca, "esc": list(esc),
                         "lab_only": lab_only}))


def run_correlate(store):
    r = StubReport()
    chains = correlate.run(r, store, None)
    return chains, r


# ---- CLI runner ----
class _TtyIO(io.StringIO):
    def __init__(self, tty):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


class _Stdin:
    def __init__(self, tty):
        self._tty = tty

    def isatty(self):
        return self._tty

    def read(self, *a):
        return ""


def run_cli(args, stdin_tty=False, stdout_tty=False, stderr_tty=False, env=None, cols=100):
    """Invoke secrethound.main() in-process with patched argv / streams /
    isatty / terminal size / env. Returns (rc, stdout_text, stderr_text).
    env: dict of overrides (None value = unset). Everything is restored."""
    import secrethound
    old = (sys.argv, sys.stdin, sys.stdout, sys.stderr, shutil.get_terminal_size)
    saved_env = {k: os.environ.get(k) for k in (env or {})}
    for k, v in (env or {}).items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    sys.argv = ["secrethound"] + list(args)
    so, se = _TtyIO(stdout_tty), _TtyIO(stderr_tty)
    sys.stdin, sys.stdout, sys.stderr = _Stdin(stdin_tty), so, se
    shutil.get_terminal_size = lambda *a, **k: os.terminal_size((cols, 24))
    try:
        rc = secrethound.main()
    finally:
        sys.argv, sys.stdin, sys.stdout, sys.stderr, shutil.get_terminal_size = old
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return rc, so.getvalue(), se.getvalue()


class NetworkTrap:
    """Context manager: every socket / urllib / http.client / subprocess /
    os.system entry point raises AssertionError and is recorded in .calls.
    This is the executable form of the OSCP+ offline guarantee."""
    TARGETS = (("socket", "socket"), ("socket", "create_connection"), ("socket", "getaddrinfo"),
               ("socket", "gethostbyname"), ("socket", "gethostbyaddr"), ("socket", "socketpair"),
               ("urllib.request", "urlopen"), ("urllib.request", "Request"),
               ("http.client", "HTTPConnection"), ("http.client", "HTTPSConnection"),
               ("subprocess", "Popen"), ("subprocess", "run"), ("subprocess", "call"),
               ("subprocess", "check_output"), ("subprocess", "check_call"),
               ("os", "system"), ("os", "popen"))

    def __init__(self):
        self.calls = []
        self._saved = []

    def __enter__(self):
        import importlib
        # import every target module BEFORE patching anything: `ssl` does
        # `class SSLSocket(socket)` at import time, so a function in place of
        # socket.socket would blow up the import itself, not the tool.
        mods = {modname: importlib.import_module(modname) for modname, _ in self.TARGETS}
        for modname, attr in self.TARGETS:
            mod = mods[modname]
            self._saved.append((mod, attr, getattr(mod, attr)))
            name = f"{modname}.{attr}"

            def _boom(*a, _n=name, **k):
                self.calls.append(_n)
                raise AssertionError("OFFLINE GUARANTEE VIOLATED: " + _n)
            setattr(mod, attr, _boom)
        return self

    def __exit__(self, *exc):
        for mod, attr, orig in reversed(self._saved):
            setattr(mod, attr, orig)
        return False


# ---- shared fixture texts (exact; reused by ad / pivot / offline modules) ----
RUBEUS_ASKTGT = ("[*] Action: Ask TGT\n\n"
    "[*] Using rc4_hmac hash: " + NT.upper() + "\n"
    "[*] Building AS-REQ (w/ preauth) for: 'CORP.LOCAL\\svc_backup'\n"
    "[+] TGT request successful!\n"
    "[*] base64(ticket.kirbi):\n\n      doIF7jCCBeqgAwIBBaEDAgEWoo\n\n"
    "  ServiceName              :  krbtgt/CORP.LOCAL\n"
    "  ServiceRealm             :  CORP.LOCAL\n"
    "  UserName                 :  svc_backup\n"
    "  UserRealm                :  CORP.LOCAL\n")
RUBEUS_S4U = ("[*] Action: S4U\n\n"
    "[*] Building S4U2self request for: 'CORP.LOCAL\\svc_web'\n"
    "[*] Sending S4U2self request\n"
    "[+] S4U2self success!\n"
    "[*] Got a TGS for 'administrator' to 'svc_web@CORP.LOCAL'\n"
    "[*] Impersonating user 'administrator' to target SPN 'CIFS/dc01.corp.local'\n"
    "[*] Building S4U2proxy request for service: 'CIFS/dc01.corp.local'\n"
    "[+] S4U2proxy success!\n"
    "  ServiceName              :  CIFS/dc01.corp.local\n"
    "  UserName                 :  administrator\n")
PIVOT_ALL = ("$ ./chisel server -p 8080 --reverse\n"
    "2024/01/15 15:15:22 server: Listening on http://0.0.0.0:8080\n"
    "2024/01/15 15:15:23 client: Connected (Latency 12ms)\n"
    "INFO[0000] Listening on 0.0.0.0:11601\n"
    "INFO[0142] Agent joined.       name=WEB01.corp.local remote=10.10.14.5:44210\n"
    "ssh -L 8080:10.20.30.40:80 user@jumphost\n"
    "ssh -R 4444:127.0.0.1:4444 user@attacker\n"
    "ssh -D 9050 user@jumphost\n"
    "netsh interface portproxy add v4tov4 connectaddress=10.20.30.40 listenport=8080 connectport=445 listenaddress=0.0.0.0\n"
    "socat TCP4-LISTEN:8080,fork TCP4:10.20.30.40:445\n")
SECRETSDUMP = ("Administrator:500:" + BLANK_LM + ":" + NT + ":::\n"
    "Guest:501:" + BLANK_LM + ":31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    "CORP\\jdoe:1105:" + BLANK_LM + ":" + NT + ":::\n")
NMAP_DC = ("Nmap scan report for dc01.corp.local (10.10.11.5)\n"
           "445/tcp open  microsoft-ds\n5985/tcp open  wsman\n88/tcp open kerberos-sec\n")


def make_loot_dir():
    """<tmp>/dc01/{secretsdump.txt, notes.txt, nmap.txt}; returns (root, notes_path).
    Caller rmtree's root."""
    root = tempfile.mkdtemp(prefix="sh-loot-")
    d = os.path.join(root, "dc01")
    os.makedirs(d)
    with open(os.path.join(d, "secretsdump.txt"), "w") as fh:
        fh.write(SECRETSDUMP)
    notes = os.path.join(d, "notes.txt")
    with open(notes, "w") as fh:
        fh.write("creds: jdoe:Summer2024!\n" + RUBEUS_ASKTGT + PIVOT_ALL)
    with open(os.path.join(d, "nmap.txt"), "w") as fh:
        fh.write(NMAP_DC)
    return root, notes


def hint_names_banned_tool(hint):
    """True when a hint= string names an exam-prohibited tool."""
    low = (hint or "").lower()
    return any(t in low for t in BANNED_TOOLS)


_MTP_PAYLOAD = re.compile(
    r"meterpreter[/_]"                    # windows/x64/meterpreter/reverse_tcp, meterpreter_reverse_tcp
    r"|meterpreter\s*>"                   # meterpreter > prompt
    r"|\bpayload[\s=]+\S*meterpreter")    # set payload .../meterpreter..., PAYLOAD=...


def suggests_meterpreter(text):
    """True when a hint SUGGESTS a meterpreter payload (payload path, prompt,
    or `set payload`). Prose that explains the quota ("only a meterpreter
    payload binds the one-target quota", "non-meterpreter = quota-free") is
    the tool warning the operator, not a suggestion, so it does not count.
    compliance.is_meterpreter() is a substring check meant for payload
    strings, not free-form hint prose."""
    return bool(_MTP_PAYLOAD.search((text or "").lower()))
