"""evidence.py - the shared spine the correlation engine consumes.

Every ingest adapter + the notes/inventory analyzers write Evidence records into
a single Store. The Store carries a host canonicaliser (the critic's B5 fix) so
an IP from nmap, an FQDN from BloodHound and a short name from notes all resolve
to ONE host entity - otherwise chains never connect.
"""
import re
from dataclasses import dataclass, field

_IP = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


@dataclass
class Evidence:
    kind: str                       # host|service|user|cred|hash|plaintext|share|
                                    # bh_fact|nxc_result|ldap_attr|cert_template|web
    host: str = ""                  # canonicalised IP or name
    port: int = 0
    service: str = ""               # smb|winrm|mssql|ssh|mysql|ldap|kerberos|http
    user: str = ""
    domain: str = ""
    cred: str = ""                  # plaintext password if known
    hash: str = ""                  # raw hash value
    hash_mode: str = ""             # hashcat mode
    plaintext: str = ""             # cracked / recovered plaintext
    fact: str = ""                  # kerberoastable|asreproastable|dc|admincount|
                                    # pwned|unconstrained|admin_to|esc1|...
    source: str = ""                # absolute path the record came from
    line: int = None
    da_distance: int = None         # BloodHound hops-to-DA, if known
    lab_only: bool = False          # spoofing/relay-derived -> never a top action
    meta: dict = field(default_factory=dict)


class Store:
    def __init__(self):
        self.items = []
        self.cracked = set()            # normalised hash values found in potfiles
        self.lockout_threshold = None   # domain account-lockout threshold, if known
        # name<->ip resolver (populated by inventory.py + adapters)
        self._name2ip = {}              # lc short/fqdn -> ip
        self._ip2names = {}             # ip -> set(names)

    # ── host canonicalisation ──
    # iter-14 audit fixes (workflow w3cghu9kx):
    #   - learn_host with no IP was a no-op for short<->fqdn alias mapping
    #   - learn_host blindly overwrote IP when same short name appeared in
    #     two subnets (re-imaged host, FQDN from different domains)
    #   - canon didn't lowercase / normalize IPv6 (round-trip miss)
    def _norm_ip(self, s):
        """Normalise an IP string: lowercase + IPv6 canonical compression
        when possible. Returns '' if not a valid IP."""
        import ipaddress
        s = (s or "").strip()
        if not s:
            return ""
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            return ""

    def learn_host(self, ip="", names=()):
        if isinstance(names, str):
            names = [names]
        ip = self._norm_ip(ip)
        lc = [(n or "").strip().lower() for n in names if n and (n or "").strip()]
        # iter-14: always record short<->fqdn alias even when ip is empty so
        # canon can later collapse short and fqdn forms.
        if not hasattr(self, "_aliases"):
            self._aliases = {}
        for n in lc:
            short = n.split(".")[0]
            if short and short != n:
                self._aliases.setdefault(short, set()).add(n)
                self._aliases.setdefault(n, set()).add(short)
        if ip:
            for n in lc:
                # iter-14: collision detection - if a NAME maps to a DIFFERENT
                # ip, keep first-writer (don't clobber). For the short label,
                # only set if not already pointing somewhere else.
                if n in self._name2ip and self._name2ip[n] != ip:
                    self.items.append(Evidence(
                        kind="host", fact="name_collision",
                        meta={"name": n, "ips": [self._name2ip[n], ip]}))
                else:
                    self._name2ip[n] = ip
                short = n.split(".")[0]
                if short and short != n:
                    if short not in self._name2ip:
                        self._name2ip[short] = ip
                    elif self._name2ip[short] != ip:
                        # don't overwrite a DIFFERENT short-label mapping;
                        # the FQDN still resolves correctly via the full key.
                        pass
            s = self._ip2names.setdefault(ip, set())
            for n in lc:
                s.add(n)

    def canon(self, host):
        """resolve any host token to a canonical key (IP when known)."""
        if not host:
            return ""
        h = host.strip().lower()
        # iter-14: normalise IPv6 too (was IPv4-only)
        ip = self._norm_ip(h)
        if ip:
            return ip
        return self._name2ip.get(h) or self._name2ip.get(h.split(".")[0]) or h

    def names_for(self, host):
        ip = self.canon(host)
        return self._ip2names.get(ip, set())

    # ── records ──
    def add(self, ev):
        ev.host = self.canon(ev.host) if ev.host else ev.host
        self.items.append(ev)
        return ev

    def by_kind(self, *k):
        return [e for e in self.items if e.kind in k]

    def services_on(self, host, names):
        c = self.canon(host)
        return [e for e in self.items
                if e.kind == "service" and (not host or self.canon(e.host) == c)
                and e.service in names]

    def hosts_with_service(self, names):
        return sorted({e.host for e in self.items
                       if e.kind == "service" and e.service in names and e.host})

    def users_txt(self):
        # iter-16: filter machine accounts (HOSTNAME$ format from NTDS dumps).
        # These represent computer objects, not user accounts; spraying their
        # NT hash against another machine is meaningless and floods spray
        # output with false negatives. Operator wants users.txt for HUMAN
        # accounts.
        return sorted({e.user for e in self.items
                       if e.user and not e.user.endswith("$")})

    def hosts(self):
        return sorted({e.host for e in self.items if e.host})
