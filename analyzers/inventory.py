"""inventory.py - build a name<->IP resolver from the operator's OWN host files.

/etc/hosts, ~/.ssh/known_hosts and ~/.ssh/config let the correlator fill the
REAL target IP into next-step commands (instead of <DC-IP>) and merge a cred
written against 'dc01' with hashes found under the IP-named loot dir. All local
files, read-only - exam-legal.
"""
import os
import re

_HOSTS_LINE = re.compile(r'^\s*([0-9a-fA-F:.]+)\s+(.+)$')
_SSH_HOST = re.compile(r'^\s*Host\s+(.+)$', re.I)
_SSH_KV = re.compile(r'^\s*(HostName|User|Port|IdentityFile)\s+(\S+)', re.I)


def parse_etc_hosts(path, store):
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                m = _HOSTS_LINE.match(line)
                if not m:
                    continue
                ip = m.group(1)
                if ip.startswith("127.") or ip in ("::1",):
                    continue
                names = m.group(2).split()
                store.learn_host(ip=ip, names=names)
    except OSError:
        pass


def parse_known_hosts(path, store):
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(("#", "|1|", "@")):
                    continue
                hostfield = line.split()[0]
                for h in hostfield.split(","):
                    h = h.strip("[]").split(":")[0]
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', h):
                        store.learn_host(ip=h)
                    elif h:
                        store.learn_host(names=[h])
    except OSError:
        pass


def parse_ssh_config(path, store):
    try:
        with open(path, "r", errors="ignore") as fh:
            alias, hostname = "", ""
            for line in fh:
                mh = _SSH_HOST.match(line)
                if mh:
                    alias, hostname = mh.group(1).strip(), ""
                    continue
                mk = _SSH_KV.match(line)
                if mk and mk.group(1).lower() == "hostname":
                    hostname = mk.group(2).strip()
                    if alias and hostname:
                        store.learn_host(ip=hostname if re.match(r'^\d', hostname) else "",
                                         names=[a for a in alias.split() if a != "*"] +
                                               ([hostname] if not re.match(r'^\d', hostname) else []))
    except OSError:
        pass


def load(report, store, extra_hosts=None):
    """populate the store's resolver from local host files."""
    parse_etc_hosts("/etc/hosts", store)
    home = os.path.expanduser("~")
    parse_known_hosts(os.path.join(home, ".ssh", "known_hosts"), store)
    parse_ssh_config(os.path.join(home, ".ssh", "config"), store)
    for p in (extra_hosts or []):
        parse_etc_hosts(p, store)
    learned = len(store._ip2names)
    if learned:
        report.add("INFO", "RECON", "/etc/hosts", None,
                   f"host inventory: {learned} IPs mapped (names↔IP for chains)")
