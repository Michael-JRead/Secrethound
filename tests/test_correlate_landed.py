"""iter-312: correlator rules for LANDED evidence + the lint-drop guard.

Before iter-312, ~20 evidence kinds emitted by keyword.py / privesc.py were
never read by core/correlate.py, so the ranked ATTACK PATH ignored Pwn3d!,
shell prompts, minted TGTs, completed S4U, staged hives, live tunnels,
privesc vectors and the Metasploit quota. And two chains (R16, R17) were
silently deleted by the compliance gate because a command line was prose.
"""
import unittest
from unittest import mock

from tests._helpers import StubReport, ad_store, add_plaintext
from analyzers import compliance
from analyzers.ingest.evidence import Store, Evidence
from core import correlate


def run(store, report=None, root="/loot"):
    r = report or StubReport()
    r.root = root
    rejected = []
    real = compliance.lint_command

    def spy(cmd, tagged=False):
        ok, why = real(cmd, tagged)
        if not ok:
            rejected.append((cmd, why))
        return ok, why

    with mock.patch.object(compliance, "lint_command", spy):
        chains = correlate.run(r, store, None)
    return chains, r, rejected


def by_rule(chains, rule):
    return [c for c in chains if c.rule == rule]


def dc_store():
    s = Store()
    s.add(Evidence(kind="host", host="10.10.10.5", fact="dc", source="/loot/dc01/nmap.txt"))
    s.learn_host("10.10.10.5", ["dc01.corp.local"])
    s.add(Evidence(kind="service", host="10.10.10.5", service="smb", port=445,
                   source="/loot/dc01/nmap.txt"))
    return s


class MsfQuota(unittest.TestCase):
    def _mtp(self, src, mtp=True):
        return Evidence(kind="msfvenom_payload", source=src, line=1,
                        meta={"meterpreter": str(mtp), "quota_count": "1",
                              "payload": "windows/x64/meterpreter/reverse_tcp" if mtp
                              else "windows/x64/shell_reverse_tcp",
                              "outfile": "m.exe", "lhost": "10.10.14.5", "lport": "443"})

    def test_two_dirs_is_top_chain(self):
        s = dc_store()
        s.add(self._mtp("/loot/web01/t.txt"))
        s.add(self._mtp("/loot/dc01/t.txt"))
        add_plaintext(s)
        chains, _, rej = run(s)
        self.assertEqual(rej, [])
        self.assertEqual(chains[0].rule, "R-MSF-QUOTA", [c.rule for c in chains[:3]])
        self.assertEqual(chains[0].score, 16.0)
        self.assertIn("QUOTA BLOWN", chains[0].summary)

    def test_single_meterpreter_or_shell_only_no_chain(self):
        s = dc_store()
        s.add(self._mtp("/loot/web01/t.txt"))
        self.assertEqual(by_rule(run(s)[0], "R-MSF-QUOTA"), [])
        s = dc_store()
        s.add(self._mtp("/loot/web01/a.txt", mtp=False))
        s.add(self._mtp("/loot/dc01/b.txt", mtp=False))
        self.assertEqual(by_rule(run(s)[0], "R-MSF-QUOTA"), [])

    def test_quota_chain_never_suggests_msfconsole(self):
        s = dc_store()
        s.add(self._mtp("/loot/a/t.txt"))
        s.add(self._mtp("/loot/b/t.txt"))
        q = by_rule(run(s)[0], "R-MSF-QUOTA")[0]
        for cmd in q.commands:
            if not cmd.lstrip().startswith("#"):
                self.assertNotIn("msfconsole", cmd)
                self.assertNotIn("meterpreter", cmd.split("#", 1)[0])


class OwnedHosts(unittest.TestCase):
    def _store(self, session=True, da=True):
        s = Store()
        s.add(Evidence(kind="service", host="10.10.10.7", service="smb", port=445,
                       source="/loot/ws01/nmap.txt"))
        s.add(Evidence(kind="admin", user="svc_web", host="10.10.10.7", domain="CORP",
                       source="/loot/ws01/nxc.txt", line=4, meta={"cred_kind": "plaintext"}))
        s.add(Evidence(kind="plaintext", user="svc_web", plaintext="P@ss",
                       source="/loot/ws01/notes.txt", line=1))
        if da:
            s.add(Evidence(kind="user", user="da_admin", fact="admincount",
                           source="/loot/bh/users.json"))
        if session:
            s.add(Evidence(kind="logged_on_session", user="da_admin", host="10.10.10.7",
                           domain="CORP", source="/loot/ws01/pv.txt", line=9))
        return s

    def test_da_session_lsass_now(self):
        chains, _, rej = run(self._store())
        self.assertEqual(rej, [])
        c = by_rule(chains, "R-LSASS-NOW")
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].score, 13.5)
        self.assertTrue(c[0].commands[0].startswith(
            "netexec smb 10.10.10.7 -u 'svc_web' -p 'P@ss' -M lsassy"), c[0].commands[0])

    def test_no_session_psexec(self):
        chains, _, _ = run(self._store(session=False))
        self.assertEqual(by_rule(chains, "R-LSASS-NOW"), [])
        p = by_rule(chains, "R-PSEXEC")
        self.assertEqual(len(p), 1)
        # domain comes from the Pwn3d! record itself (netexec's own report)
        self.assertIn("impacket-psexec 'CORP/svc_web:P@ss'@10.10.10.7", p[0].commands[0])

    def test_shell_without_cred_owned_dump(self):
        s = Store()
        s.add(Evidence(kind="shell_landed", host="web01.corp.local", source="/loot/web01/ps.txt",
                       line=2, meta={"method": "psremoting"}))
        c = by_rule(run(s)[0], "R-OWNED-DUMP")
        self.assertEqual(len(c), 1)
        self.assertIn("psremoting", c[0].summary)


class Tickets(unittest.TestCase):
    def test_ccache_da_ptt_just_dc(self):
        s = dc_store()
        s.add(Evidence(kind="ccache", user="administrator", source="/loot/dc01/getst.txt",
                       line=3, meta={"path": "/loot/dc01/administrator.ccache"}))
        chains, _, rej = run(s)
        self.assertEqual(rej, [])
        c = by_rule(chains, "R-PTT-LATERAL")
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].score, 14.2)
        self.assertIn("-just-dc", c[0].commands[-1])

    def test_rubeus_tgt_converts_first(self):
        s = dc_store()
        s.add(Evidence(kind="tgt_landed", user="svc_backup", domain="CORP.LOCAL",
                       source="/loot/ws01/rubeus.txt", line=5,
                       meta={"tool": "rubeus_asktgt"}))
        c = by_rule(run(s)[0], "R-PTT-LATERAL")[0]
        self.assertTrue(any("impacket-ticketConverter" in x for x in c.commands[:2]))
        self.assertFalse(any("Rubeus.exe" in x.split("#", 1)[0] for x in c.commands))

    def test_s4u_cifs_dc(self):
        s = dc_store()
        s.add(Evidence(kind="delegation_landed", user="Administrator",
                       source="/loot/ws01/rubeus.txt", line=7,
                       meta={"target_spn": "cifs/dc01.corp.local", "tool": "rubeus_s4u"}))
        chains, _, rej = run(s)
        self.assertEqual(rej, [])
        c = by_rule(chains, "R-DELEG-LANDED")[0]
        self.assertEqual(c.score, 11.7)
        self.assertTrue(any("-just-dc" in x for x in c.commands))

    def test_s4u_mssql(self):
        s = dc_store()
        s.add(Evidence(kind="delegation_landed", user="Administrator", source="/loot/x/r.txt",
                       meta={"target_spn": "MSSQLSvc/sql01.corp.local:1433"}))
        c = by_rule(run(s)[0], "R-DELEG-LANDED")[0]
        self.assertTrue(any("impacket-mssqlclient -k -no-pass" in x for x in c.commands))


class HivesPivotPolicy(unittest.TestCase):
    def test_staged_sam_system_security(self):
        s = Store()
        for h in ("SAM", "SYSTEM", "SECURITY"):
            s.add(Evidence(kind="hive_file", source="/loot/ws01/shell.txt", line=2,
                           meta={"hive": h, "path": f"C:\\Temp\\{h}.hiv"}))
        chains, _, rej = run(s)
        self.assertEqual(rej, [])
        c = by_rule(chains, "R-HIVE-OFFLINE")
        self.assertEqual(len(c), 1)
        self.assertIn("-security", " ".join(c[0].commands))

    def test_ifm_ntds(self):
        s = Store()
        s.add(Evidence(kind="ntds_dump", source="/loot/dc01/ntdsutil.txt", line=4,
                       meta={"path": "C:\\ifm"}))
        c = by_rule(run(s)[0], "R-HIVE-OFFLINE")[0]
        self.assertIn("NTDS.dit", c.summary)
        self.assertTrue(any("C:/ifm/Active Directory/ntds.dit" in x for x in c.commands))

    def test_pivot_scans_unscanned_hosts(self):
        s = Store()
        s.add(Evidence(kind="pivot_landed", source="/loot/web01/t.txt", line=1,
                       meta={"tool": "chisel", "role": "client", "status": "connected"}))
        s.add(Evidence(kind="host", host="172.16.1.5", source="/loot/web01/n.txt"))
        s.add(Evidence(kind="logged_on_session", user="x", host="172.16.1.6",
                       source="/loot/web01/pv.txt"))
        chains, _, rej = run(s)
        self.assertEqual(rej, [])
        c = by_rule(chains, "R-PIVOT-SCAN")[0]
        self.assertTrue(c.commands[0].startswith("proxychains -q nmap -sT -Pn -n --open"))
        self.assertIn("172.16.1.5 172.16.1.6", c.commands[0])

    def test_ligolo_route_no_proxychains(self):
        s = Store()
        s.add(Evidence(kind="pivot_landed", host="web01", source="/loot/web01/l.txt",
                       meta={"tool": "ligolo-ng", "role": "proxy"}))
        c = by_rule(run(s)[0], "R-PIVOT-SCAN")[0]
        self.assertFalse(any(x.startswith("proxychains") for x in c.commands))

    def test_password_policy_feeds_lockout_guard(self):
        s = dc_store()
        s.add(Evidence(kind="password_policy", source="/loot/dc01/netacc.txt",
                       meta={"lockout_threshold": "5", "lockout_window": "30",
                             "min_length": "7"}))
        add_plaintext(s)
        run(s)
        self.assertEqual(s.lockout_threshold, 5)


class AclBridgeAndPrivesc(unittest.TestCase):
    def test_powerview_writemember_routes_to_addmember(self):
        s = ad_store()
        add_plaintext(s)
        s.add(Evidence(kind="acl", user="Domain Admins", source="/loot/dc01/pv.txt", line=3,
                       meta={"right": "WriteMember", "principal_sid": "S-1-5-21-1-2-3-1105",
                             "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=local"}))
        self.assertTrue(by_rule(run(s)[0], "R-ADDMEMBER"))

    def test_extendedright_is_ignored(self):
        s = ad_store()
        add_plaintext(s)
        s.add(Evidence(kind="acl", user="svc", source="/loot/dc01/pv.txt",
                       meta={"right": "ExtendedRight", "principal_sid": "S-1-5-21-9"}))
        before = len(run(ad_store())[0])
        self.assertLessEqual(len([c for c in run(s)[0] if c.rule.startswith("R-")]),
                             before + 10)   # no crash, no bogus ACL chain
        self.assertEqual([c for c in run(s)[0] if "svc" in c.summary and "ExtendedRight" in c.summary], [])

    def test_privesc_vector_surfaces_in_attack_path(self):
        s = Store()
        r = StubReport()
        r.add("CRITICAL", "PRIVESC", "/loot/box1/whoami.txt", 6,
              "SeImpersonatePrivilege held -> Potato/PrintSpoofer -> SYSTEM",
              hint="PrintSpoofer64.exe -i -c cmd  |  GodPotato-NET4.exe -cmd \"cmd /c whoami\"")
        s.add(Evidence(kind="privesc_vector", fact="se_impersonate", source="/loot/box1/whoami.txt",
                       line=6, meta={"technique": "se_impersonate", "os": "windows"}))
        chains, _, rej = run(s, report=r)
        self.assertEqual(rej, [])
        c = by_rule(chains, "R-PRIVESC")
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].score, 10.8)
        self.assertIn("box1", c[0].summary)
        self.assertTrue(any("proof.txt" in x for x in c[0].commands))


class KeywordSourcedPrivesc(unittest.TestCase):
    def test_sudo_nopasswd_from_keyword_surfaces(self):
        r = StubReport()
        r.add("CRITICAL", "ASSIGNED SECRETS", "/loot/box2/sudo.txt", 6,
              "sudo -l NOPASSWD (as root) -> /usr/bin/find",
              hint="sudo find . -exec /bin/sh \\; -quit")
        c = by_rule(run(Store(), report=r)[0], "R-PRIVESC")
        self.assertEqual(len(c), 1)
        self.assertIn("box2", c[0].summary)
        self.assertTrue(c[0].commands[0].startswith("sudo find"), c[0].commands)

    def test_same_technique_two_sources_ranks_once(self):
        r = StubReport()
        r.add("HIGH", "PRIVESC", "/loot/box3/suid.txt", 3,
              "SUID-root GTFOBins-able binary: /usr/bin/find", hint="x")
        r.add("HIGH", "INTERESTING FILES", "/loot/box3/ls.txt", 9,
              "SUID-root GTFOBins-able binary: /usr/bin/find", hint="y")
        s = Store()
        s.add(Evidence(kind="privesc_vector", fact="suid_gtfobins", source="/loot/box3/suid.txt",
                       line=3, meta={"technique": "suid_gtfobins", "os": "linux"}))
        self.assertEqual(len(by_rule(run(s, report=r)[0], "R-PRIVESC")), 1)


class NoChainDroppedByLint(unittest.TestCase):
    """The R16/R17 failure mode: one prose command line -> whole chain gone.
    Build a store that triggers as many rules as possible and assert the
    compliance gate rejected nothing."""

    def test_everything_store_has_zero_lint_rejections(self):
        s = dc_store()
        add_plaintext(s, user="alice", pw="P@ss")
        s.add(Evidence(kind="admin", user="alice", host="10.10.10.5", source="/loot/dc01/nxc.txt"))
        s.add(Evidence(kind="ccache", user="alice", source="/loot/dc01/x.txt", meta={"path": "a.ccache"}))
        s.add(Evidence(kind="pfx", user="alice", source="/loot/dc01/x.txt", meta={"path": "a.pfx"}))
        s.add(Evidence(kind="tgt_landed", user="bob", source="/loot/ws/r.txt"))
        s.add(Evidence(kind="delegation_landed", user="administrator", source="/loot/ws/r.txt",
                       meta={"target_spn": "http/web01.corp.local"}))
        s.add(Evidence(kind="pivot_landed", source="/loot/ws/t.txt",
                       meta={"tool": "netsh_portproxy", "connect_addr": "10.20.0.4",
                             "connect_port": "445", "listen_port": "8445"}))
        s.add(Evidence(kind="ntds_dump", source="/loot/dc01/i.txt", meta={"path": "C:\\ifm"}))
        _, _, rej = run(s)
        self.assertEqual(rej, [], "\n".join(f"{w}: {c}" for c, w in rej))


if __name__ == "__main__":
    unittest.main()
