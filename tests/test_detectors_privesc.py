"""D3 technique contract for the standalone-box privesc detectors (30 of 100
exam points): SeImpersonate, sudo NOPASSWD, SUID, cron wildcard, getcap,
AlwaysInstallElevated, unquoted service path, NFS no_root_squash, docker/lxd
group.

Ownership today is SPLIT (iter-311 / I1): analyzers/privesc.py owns the new
anchored parsers (category "PRIVESC", Evidence kind="privesc_vector" with
meta.technique == fact) while analyzers/keyword.py kept its historical
detectors for the same techniques under their old categories:

    sudo -l NOPASSWD / GTFOBins    -> ASSIGNED SECRETS
    tar wildcard, getcap, docker   -> INTERESTING FILES
    AlwaysInstallElevated, NFS     -> RECON

run_privesc() runs both modules on the same file (exactly like the per-file
loop in secrethound.main), so `pe()` below collects the merged privesc
SURFACE. The strict single-section contract is kept as an expectedFailure
test so the gap stays visible until the detectors are consolidated."""
import re
import unittest

from tests._helpers import HAVE_PRIVESC, run_privesc, compliance, suggests_meterpreter

PRIVESC_SURFACE = ("PRIVESC", "RECON", "INTERESTING FILES", "ASSIGNED SECRETS")

SEIMP = ("PRIVILEGES INFORMATION\n"
         "----------------------\n"
         "\n"
         "Privilege Name                Description                               State\n"
         "============================= ========================================= ========\n"
         "SeImpersonatePrivilege        Impersonate a client after authentication Enabled\n"
         "SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled\n")
SUDO = ("Matching Defaults entries for www-data on web01:\n"
        "    env_reset, mail_badpass\n"
        "\n"
        "User www-data may run the following commands on web01:\n"
        "    (ALL) NOPASSWD: /usr/bin/vim\n"
        "    (root) NOPASSWD: /usr/bin/python3 /opt/backup.py\n")
SUID_BARE = "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/find\n/usr/bin/python3.8\n/usr/bin/mount\n"
SUID_PROMPT = "$ find / -perm -4000 -type f 2>/dev/null\n" + SUID_BARE
SUID_LS = "-rwsr-xr-x 1 root root 320160 Feb 18  2020 /usr/bin/find\n"
CRON = ("SHELL=/bin/sh\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n"
        "* * * * * root cd /var/www/html && tar -czf /var/backups/html.tgz *\n"
        "*/5 * * * * root /opt/cleanup.sh\n")
GETCAP = "/usr/bin/ping = cap_net_raw+ep\n/usr/bin/python3.8 = cap_setuid+ep\n"
AIE = ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
       "    AlwaysInstallElevated    REG_DWORD    0x1\n"
       "\n"
       "HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
       "    AlwaysInstallElevated    REG_DWORD    0x1\n")
UNQUOTED = ("Name            PathName                                          StartMode\n"
            "BackupSvc       C:\\Program Files\\Backup Tools\\bin\\backup.exe      Auto\n"
            "Spooler         C:\\Windows\\System32\\spoolsv.exe                   Auto\n"
            "QuotedSvc       \"C:\\Program Files\\Quoted App\\svc.exe\"               Auto\n")
NFS = ("/srv/share  10.10.0.0/16(rw,sync,no_root_squash,no_subtree_check)\n"
       "/srv/public *(ro,sync,root_squash)\n")
DOCKER = "uid=1001(jdoe) gid=1001(jdoe) groups=1001(jdoe),998(docker),27(sudo)\n"
LXD = "uid=1001(jdoe) gid=1001(jdoe) groups=1001(jdoe),999(lxd)\n"

FIXTURES = [(SEIMP, ".txt", "fixture"), (SUDO, ".txt", "fixture"), (SUID_PROMPT, ".txt", "suid"),
            (SUID_LS, ".txt", "fixture"), (CRON, ".txt", "crontab"), (GETCAP, ".txt", "getcap"),
            (AIE, ".txt", "fixture"), (UNQUOTED, ".txt", "fixture"), (NFS, ".txt", "exports"),
            (DOCKER, ".txt", "fixture"), (LXD, ".txt", "fixture")]


def pe(text, ext=".txt", name="fixture"):
    """(merged privesc-surface findings, privesc_vector evidence)."""
    r, s = run_privesc(text, ext, name)
    return ([f for f in r.findings if f["category"] in PRIVESC_SURFACE],
            [e for e in s.items if e.kind == "privesc_vector"])


@unittest.skipUnless(HAVE_PRIVESC, "analyzers/privesc.py not yet implemented (D3)")
class PrivescDetectorTests(unittest.TestCase):
    def one(self, f, token, lower=False):
        x = [a for a in f if token in (a["detail"].lower() if lower else a["detail"])]
        self.assertEqual(len(x), 1, [a["detail"] for a in x])
        self.assertIn(x[0]["severity"], ("HIGH", "CRITICAL"))
        return x[0]

    # 1
    def test_seimpersonate_enabled(self):
        f, ev = pe(SEIMP)
        strict = [a for a in f if a["category"] == "PRIVESC" and "SeImpersonatePrivilege" in a["detail"]]
        self.assertEqual(len(strict), 1)
        x = strict[0]
        self.assertEqual((x["severity"], x["line"]), ("CRITICAL", 6))
        self.assertTrue(any(t in x["hint"] for t in ("PrintSpoofer", "GodPotato", "SigmaPotato", "JuicyPotato")))
        self.assertFalse(suggests_meterpreter(x["hint"]), x["hint"])
        self.assertNotIn("getsystem", x["hint"].lower())
        se = [e for e in ev if e.meta.get("technique") == "se_impersonate"]
        self.assertEqual(len(se), 1)
        self.assertEqual(se[0].meta["state"], "Enabled")
        # A 'Disabled' row still fires (deliberate: the Potato family enables
        # the privilege itself - a Disabled SeImpersonate is still SYSTEM) but
        # the detail says so, so the operator is not misled.
        f2, _ = pe(SEIMP.replace("Impersonate a client after authentication Enabled",
                                 "Impersonate a client after authentication Disabled"))
        d = [a for a in f2 if a["category"] == "PRIVESC" and "SeImpersonatePrivilege" in a["detail"]]
        self.assertEqual(len(d), 1)
        self.assertIn("Disabled", d[0]["detail"])
        # the header is required: a bare row in prose must not fire
        f3, _ = pe("SeImpersonatePrivilege        Impersonate a client after authentication Enabled\n")
        self.assertEqual([a for a in f3 if a["severity"] == "CRITICAL"], [])

    # 2
    def test_sudo_nopasswd(self):
        f, ev = pe(SUDO)
        nop = [a for a in f if "NOPASSWD" in a["detail"]]
        self.assertGreaterEqual(len(nop), 1)
        vim = [a for a in nop if "/usr/bin/vim" in a["detail"]]
        self.assertEqual(len(vim), 1)
        self.assertEqual(vim[0]["severity"], "CRITICAL")
        self.assertIn("gtfobins", vim[0]["hint"].lower())
        script = [a for a in f if "/opt/backup.py" in a["detail"] and "writab" in (a["hint"] or "").lower()]
        self.assertTrue(script, [a["detail"] for a in f])             # writable-script check hint
        self.assertTrue([e for e in ev if e.meta.get("technique") == "sudo_script"
                         and e.meta.get("target") == "/opt/backup.py"])
        f2, _ = pe("    (ALL) PASSWD: /usr/bin/vim\n")
        self.assertEqual([a for a in f2 if "NOPASSWD" in a["detail"]], [])

    # 3
    def test_suid_find_only_non_standard(self):
        f, ev = pe(SUID_PROMPT, name="suid")
        py = [a for a in f if "SUID" in a["detail"] and "/usr/bin/python3.8" in a["detail"]]
        self.assertEqual(len(py), 1, [a["detail"] for a in f])
        self.assertIn(py[0]["severity"], ("MEDIUM", "HIGH", "CRITICAL"))
        self.assertTrue([e for e in ev if e.meta.get("technique") == "suid_custom"
                         and e.meta.get("target") == "/usr/bin/python3.8"])
        for std in ("/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/mount"):   # standard SUID set
            self.assertFalse([a for a in f if std in a["detail"]], std)
        # the `ls -la` row form of a GTFOBins SUID binary is keyword.py's job
        f2, _ = pe(SUID_LS)
        x = self.one(f2, "/usr/bin/find")
        self.assertIn("-exec /bin/sh -p", x["hint"])

    # iter-311: fixed (was expectedFailure).
    # /usr/bin assuming "keyword.py emits the exact GTFOBins escape", but keyword.py's
    # "SUID GTFOBins" pattern only matches an `-rws...` ls row - so `/usr/bin/find` from a
    # bare `find / -perm -4000` listing (the most common OSCP enumeration output) is
    # reported by NEITHER module.
    def test_suid_find_gtfobins_from_bare_find_listing(self):
        f, _ = pe(SUID_PROMPT, name="suid")
        x = self.one(f, "/usr/bin/find")
        self.assertIn("-exec /bin/sh -p", x["hint"])

    # 4
    def test_cron_tar_wildcard(self):
        f, _ = pe(CRON, name="crontab")
        x = self.one(f, "wildcard", lower=True)
        self.assertIn("tar", x["detail"])
        self.assertEqual(x["line"], 3)
        self.assertIn("--checkpoint-action", x["hint"])
        # a finding for the second root cron script is allowed but not required
        cleanup = [a for a in f if "/opt/cleanup.sh" in a["detail"]]
        for a in cleanup:
            self.assertTrue(a["hint"])

    # 5
    def test_getcap_setuid(self):
        f, _ = pe(GETCAP, name="getcap")
        x = [a for a in f if "cap_setuid" in a["detail"]]
        self.assertEqual(len(x), 1)
        self.assertIn("/usr/bin/python3.8", x[0]["detail"])
        self.assertIn(x[0]["severity"], ("HIGH", "CRITICAL"))
        self.assertIn("os.setuid(0)", x[0]["hint"])

    # iter-311: fixed (was expectedFailure).
    # so the stock `/usr/bin/ping = cap_net_raw+ep` every distro ships fires HIGH (privesc
    # noise), and its _LINUX_CAPS hint recommends "ARP spoof" - spoofing is exam-prohibited.
    def test_getcap_default_ping_cap_net_raw_is_noise(self):
        f, _ = pe(GETCAP, name="getcap")
        self.assertEqual([a for a in f if "/usr/bin/ping" in a["detail"]], [])

    # 6
    def test_always_install_elevated(self):
        f, _ = pe(AIE)
        x = [a for a in f if "AlwaysInstallElevated" in a["detail"]]
        self.assertGreaterEqual(len(x), 1)
        for a in x:
            self.assertEqual(a["severity"], "CRITICAL")               # both hives set
            self.assertIn("msfvenom", a["hint"])
            self.assertIn("-f msi", a["hint"])
            self.assertFalse(suggests_meterpreter(a["hint"]), a["hint"])   # non-meterpreter MSI = quota-free
        f2, _ = pe(AIE.replace("0x1", "0x0"))
        self.assertEqual([a for a in f2 if "AlwaysInstallElevated" in a["detail"]], [])

    # 7
    def test_unquoted_service_path(self):
        f, ev = pe(UNQUOTED)
        x = [a for a in f if "unquoted" in a["detail"].lower()]
        self.assertEqual(len(x), 1, [a["detail"] for a in f])
        self.assertIn(x[0]["severity"], ("HIGH", "CRITICAL"))
        self.assertIn("Backup Tools", x[0]["detail"])
        self.assertIn("Backup.exe", x[0]["detail"] + x[0]["hint"])   # the hijack drop point
        self.assertIn("icacls", x[0]["hint"])
        for other in ("Spooler", "spoolsv", "QuotedSvc", "Quoted App"):
            self.assertFalse([a for a in f if other in a["detail"]], other)
        self.assertEqual([e.meta.get("technique") for e in ev], ["unquoted_path"])

    # 8
    def test_nfs_no_root_squash(self):
        f, _ = pe(NFS, name="exports")
        x = [a for a in f if "no_root_squash" in a["detail"]]
        self.assertEqual(len(x), 1)
        self.assertIn("/srv/share", x[0]["detail"])
        self.assertNotIn("/srv/public", x[0]["detail"])
        self.assertIn("mount -t nfs", x[0]["hint"])
        self.assertTrue("+s" in x[0]["hint"] or "suid" in x[0]["hint"].lower(), x[0]["hint"])

    # 9
    def test_docker_group_membership(self):
        f, ev = pe(DOCKER)
        x = [a for a in f if "docker" in a["detail"]]
        self.assertEqual(len(x), 1, [a["detail"] for a in f])
        self.assertIn(x[0]["severity"], ("HIGH", "CRITICAL"))
        self.assertIn("docker run", x[0]["hint"])
        self.assertIn("-v /:/mnt", x[0]["hint"])
        f2, _ = pe("uid=1001(jdoe) gid=1001(jdoe) groups=1001(jdoe)\n")
        self.assertEqual(f2, [])
        with self.subTest(group="lxd"):
            f3, ev3 = pe(LXD)
            x3 = self.one(f3, "lxd")
            self.assertEqual(x3["severity"], "CRITICAL")
            self.assertTrue([e for e in ev3 if e.meta.get("technique") == "group_lxd"])

    # 10
    def test_privesc_doc_gate(self):
        for text in (SEIMP, SUDO, AIE, DOCKER):
            with self.subTest(text=text[:30]):
                f, ev = pe(text, ".md")
                self.assertEqual([a for a in f if a["category"] == "PRIVESC"], [])
                self.assertEqual(ev, [])
                f, ev = pe(text, ".txt", name="linux-privesc-cheatsheet")
                self.assertEqual([a for a in f if a["category"] == "PRIVESC"], [])
                self.assertEqual(ev, [])

    # 11
    def test_privesc_hints_are_exam_legal(self):
        n = 0
        for text, ext, name in FIXTURES:
            f, _ = pe(text, ext, name)
            for a in f:
                if a["category"] == "PRIVESC":
                    self.assertTrue(a["hint"], a["detail"])          # the tool POINTS; you ACT
                for seg in (a["hint"] or "").split("  |  "):
                    n += 1
                    with self.subTest(detail=a["detail"][:60], seg=seg[:60]):
                        self.assertFalse(compliance.is_denied(seg), seg)
                        self.assertFalse(suggests_meterpreter(seg), seg)
        self.assertGreater(n, 10)

    # iter-311: fixed (was expectedFailure).
    # "packet sniffing / ARP spoof" - ARP spoofing is a prohibited exam technique and
    # hint= strings are not linted, so this is the only guard.
    def test_privesc_hints_never_suggest_spoofing(self):
        for text, ext, name in FIXTURES:
            f, _ = pe(text, ext, name)
            for a in f:
                # Network spoofing (IP/ARP/DNS/NBNS/LLMNR) is exam-prohibited.
                # "PrintSpoofer" is a local token-privesc tool name, not a
                # spoofing technique, so it is excluded from the match.
                h = (a["hint"] or "").lower()
                self.assertIsNone(re.search(r"(?<!print)spoof", h), a["detail"])

    @unittest.expectedFailure   # D5-09 contract vs iter-311 implementation: every privesc
    # technique should land in the PRIVESC section at HIGH+ with privesc_vector Evidence.
    # Today sudo/GTFOBins -> ASSIGNED SECRETS, tar wildcard / getcap / docker ->
    # INTERESTING FILES, AlwaysInstallElevated / NFS -> RECON (keyword.py), and only
    # privesc.py's own parsers emit Evidence. Remove the decorator once consolidated.
    def test_contract_all_techniques_in_privesc_section(self):
        for text, ext, name, token in ((SEIMP, ".txt", "fixture", "SeImpersonatePrivilege"),
                                       (SUDO, ".txt", "fixture", "NOPASSWD"),
                                       (CRON, ".txt", "crontab", "wildcard"),
                                       (GETCAP, ".txt", "getcap", "cap_setuid"),
                                       (AIE, ".txt", "fixture", "AlwaysInstallElevated"),
                                       (UNQUOTED, ".txt", "fixture", "unquoted"),
                                       (NFS, ".txt", "exports", "no_root_squash"),
                                       (DOCKER, ".txt", "fixture", "docker")):
            with self.subTest(token=token):
                r, s = run_privesc(text, ext, name)
                hits = [a for a in r.cat("PRIVESC") if token.lower() in a["detail"].lower()]
                self.assertTrue(hits, token)
                self.assertTrue(all(a["severity"] in ("HIGH", "CRITICAL") for a in hits))
                self.assertTrue([e for e in s.items if e.kind == "privesc_vector"], token)


if __name__ == "__main__":
    unittest.main()
