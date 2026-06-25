"""ext_nmap.py - parse nmap (.xml/.gnmap/normal) + masscan into host/service
Evidence, so the correlator can fill REAL host/IPs into next-step commands and
know which services a discovered cred can be tried against.
"""
import re
import xml.etree.ElementTree as ET
from analyzers.ingest.evidence import Evidence

# nmap service name -> our normalized service tag + a one-line exam-legal hint
SERVICE_MAP = {
    21: ("ftp", "anon? ftp <ip>; creds: try found user:pass"),
    22: ("ssh", "ssh <user>@<ip>  (key: ssh -i <key>)"),
    23: ("telnet", "telnet <ip>"),
    25: ("smtp", "smtp-user-enum -M VRFY -U users.txt -t <ip>"),
    53: ("dns", "dig axfr @<ip> <domain>"),
    88: ("kerberos", "kerbrute userenum; AS-REP: impacket-GetNPUsers"),
    110: ("pop3", "creds: try found user:pass"),
    111: ("rpcbind", "showmount -e <ip>; rpcinfo -p <ip>"),
    135: ("msrpc", "impacket-rpcdump <ip>"),
    139: ("smb", "smbclient -L //<ip>; enum4linux-ng <ip>"),
    143: ("imap", "creds: try found user:pass"),
    161: ("snmp", "snmpwalk -v2c -c public <ip>"),
    389: ("ldap", "ldapsearch -x -H ldap://<ip> -b <basedn>"),
    445: ("smb", "netexec smb <ip> -u <user> -p <pass>; enum4linux-ng <ip>"),
    636: ("ldaps", "ldapsearch -x -H ldaps://<ip>"),
    1433: ("mssql", "impacket-mssqlclient <user>@<ip>"),
    1521: ("oracle", "odat / sqlplus <user>/<pass>@<ip>"),
    2049: ("nfs", "showmount -e <ip>; mount -o nolock"),
    3268: ("gc-ldap", "ldapsearch global catalog on <ip>:3268"),
    3306: ("mysql", "mysql -h <ip> -u <user> -p<pass>"),
    3389: ("rdp", "xfreerdp /u:<user> /p:<pass> /v:<ip>"),
    5432: ("postgres", "psql -h <ip> -U <user>"),
    5985: ("winrm", "evil-winrm -i <ip> -u <user> -p <pass>"),
    5986: ("winrm", "evil-winrm -i <ip> -u <user> -p <pass> -S"),
    6379: ("redis", "redis-cli -h <ip>"),
    27017: ("mongodb", "mongo <ip>"),
}
_DC_PORTS = {88, 389, 636, 3268}


def _svc(port, name):
    if port in SERVICE_MAP:
        return SERVICE_MAP[port][0]
    n = (name or "").lower()
    for k, (tag, _) in SERVICE_MAP.items():
        if tag in n:
            return tag
    if "microsoft-ds" in n or "netbios" in n:
        return "smb"
    return n or "tcp"


def detect(path, head):
    return ("<nmaprun" in head or head.startswith("<?xml") and "nmap" in head[:200].lower()
            or bool(re.search(r'^Host:\s.*\sPorts:', head, re.M))
            or "Nmap scan report for" in head
            or head.startswith("# Nmap") or "#masscan" in head[:80])


def _emit(store, report, ip, names, ports, path=""):
    if not ip and names:
        ip = ""
    if ip or names:
        store.learn_host(ip=ip, names=names)
    host = ip or (names[0] if names else "")
    openports = {p for p, _, _ in ports}
    is_dc = len(openports & _DC_PORTS) >= 2 and 445 in openports
    if host:
        store.add(Evidence(kind="host", host=host, fact="dc" if is_dc else "",
                           source=path, meta={"names": names}))
    for port, name, product in ports:
        svc = _svc(port, name)
        store.add(Evidence(kind="service", host=host, port=port, service=svc,
                           source=path, meta={"product": product}))
        hint = SERVICE_MAP.get(port, (svc, ""))[1].replace("<ip>", host or "<ip>")
        sev = "MEDIUM" if port in (445, 5985, 1433, 88, 22, 3306, 5432) else "INFO"
        report.add(sev, "RECON", path or host or "?", None,
                   f"{host} open {port}/{svc}" + (f" {product}" if product else ""),
                   hint)
    if is_dc:
        report.add("INFO", "RECON", path or host or "?", None,
                   f"likely Domain Controller ({host})")


def _parse_xml(path, store, report):
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return 0
    n = 0
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") == "down":
            continue
        ip, names = "", []
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = a.get("addr")
        for hn in host.findall("./hostnames/hostname"):
            if hn.get("name"):
                names.append(hn.get("name"))
        ports = []
        for p in host.findall("./ports/port"):
            stt = p.find("state")
            if stt is None or stt.get("state") != "open":
                continue
            svc = p.find("service")
            name = svc.get("name") if svc is not None else ""
            product = " ".join(filter(None, [
                svc.get("product") if svc is not None else "",
                svc.get("version") if svc is not None else ""])).strip()
            ports.append((int(p.get("portid")), name, product))
        if ports:
            _emit(store, report, ip, names, ports, path)
            n += len(ports)
    return n


_GNMAP = re.compile(r'^Host:\s+(\S+)\s+\(([^)]*)\)\s+Ports:\s+(.*)$')


def _parse_gnmap(path, store, report):
    n = 0
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                m = _GNMAP.match(line.strip())
                if not m:
                    continue
                ip = m.group(1)
                names = [x for x in [m.group(2).strip()] if x]
                ports = []
                for chunk in m.group(3).split(","):
                    f = chunk.strip().split("/")
                    if len(f) >= 5 and f[1] == "open":
                        ports.append((int(f[0]), f[4], (f[6] if len(f) > 6 else "").strip()))
                if ports:
                    _emit(store, report, ip, names, ports, path)
                    n += len(ports)
    except OSError:
        return 0
    return n


def parse(path, store, report):
    head = ""
    try:
        with open(path, "r", errors="ignore") as fh:
            head = fh.read(512)
    except OSError:
        return 0
    if "<nmaprun" in head or head.lstrip().startswith("<?xml"):
        return _parse_xml(path, store, report)
    if re.search(r'^Host:\s.*\sPorts:', head, re.M):
        return _parse_gnmap(path, store, report)
    # normal nmap text: best-effort (report-only, less structured)
    return _parse_gnmap(path, store, report)
