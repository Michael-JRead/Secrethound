"""THE OSCP+ guarantee: SecretHound never opens a socket, resolves a name or
shells out. Every CLI code path runs under a network/exec trap, and a static
import audit catches a `import socket` the moment anyone adds one."""
import json
import os
import re
import shutil
import tempfile
import unittest

from tests._helpers import (REPO, NT, run_cli, make_loot_dir, NetworkTrap, compliance)

_NET_IMPORT = re.compile(
    r'^\s*(?:import|from)\s+(socket|urllib|http\.client|http\.server|requests|ftplib|'
    r'smtplib|telnetlib|paramiko|asyncio|xmlrpc|ssl|socketserver|poplib|imaplib|nntplib|'
    r'subprocess)\b', re.M)
_SKIP_DIRS = {"tests", "__pycache__", "docs", ".git"}


class OfflineGuaranteeTests(unittest.TestCase):
    def setUp(self):
        self.root, self.notes = make_loot_dir()
        self.out = tempfile.mkdtemp(prefix="sh-out-")
        self.home = tempfile.mkdtemp(prefix="sh-home-")
        self.base = ["--users-out", os.path.join(self.out, "users.txt")]
        # snapshot so test_users_out_respected_and_no_repo_pollution can tell
        # a pre-existing users.txt (someone else's run) from one we wrote.
        self._pre = {p: os.path.exists(p) for p in (
            os.path.join(REPO, "users.txt"), os.path.join(os.getcwd(), "users.txt"))}

    def tearDown(self):
        for d in (self.root, self.out, self.home):
            shutil.rmtree(d, ignore_errors=True)

    def _o(self, name):
        return os.path.join(self.out, name)

    # 1
    def test_static_no_network_or_exec_imports(self):
        offenders = []
        for dirpath, dirnames, filenames in os.walk(REPO):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                p = os.path.join(dirpath, fn)
                with open(p, "r", errors="ignore") as fh:
                    src = fh.read()
                for m in _NET_IMPORT.finditer(src):
                    offenders.append(f"{os.path.relpath(p, REPO)}: {m.group(0).strip()}")
        self.assertEqual(offenders, [], "network/exec module imported:\n" + "\n".join(offenders))

    # 2
    def test_full_cli_run_makes_no_network_or_exec_calls(self):
        with NetworkTrap() as t:
            rc, so, se = run_cli([self.root, "--no-inventory", "--no-pot",
                                  "--json", self._o("f.json"), "--html", self._o("f.html"),
                                  "--csv", self._o("f.csv"), "--hashes", self._o("h.txt")]
                                 + self.base)
        self.assertEqual(rc, 0, se + so)
        self.assertEqual(t.calls, [])
        for name in ("f.json", "f.html", "f.csv", "h.txt", "users.txt"):
            self.assertTrue(os.path.exists(self._o(name)), name)
            self.assertGreater(os.path.getsize(self._o(name)), 0, name)
        with open(self._o("users.txt")) as fh:
            self.assertIn("jdoe", fh.read())

    # 3
    def test_default_flags_inventory_and_potfile_stay_local(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        os.makedirs(os.path.join(self.home, ".hashcat"))
        with open(os.path.join(self.home, ".ssh", "config"), "w") as fh:
            fh.write("Host dc01\n    HostName 10.10.11.5\n    User jdoe\n")
        with open(os.path.join(self.home, ".hashcat", "hashcat.potfile"), "w") as fh:
            fh.write(NT + ":Summer2024!\n")
        with NetworkTrap() as t:
            rc, so, se = run_cli([self.root] + self.base, env={"HOME": self.home})
        self.assertEqual(rc, 0, se + so)
        self.assertEqual(t.calls, [])

    # 4
    def test_deep_src_all_group_dir(self):
        with open(os.path.join(self.root, "dc01", "config.php"), "w") as fh:
            fh.write("<?php $db_pass = 'S3cr3tDbP@ss'; ?>\n")
        with NetworkTrap() as t:
            rc, so, se = run_cli([self.root, "--deep", "--src", "--all", "--group", "dir",
                                  "--cap", "5", "--entropy-low"] + self.base)
        self.assertEqual(rc, 0, se + so)
        self.assertEqual(t.calls, [])
        self.assertIn("S3cr3tDbP@ss", so)

    # 5
    def test_inspect_mode(self):
        with NetworkTrap() as t:
            rc, so, se = run_cli(["--inspect", self.notes])
            self.assertEqual(rc, 0)
            self.assertIn("jdoe", so)
            rc2, so2, _ = run_cli(["--inspect", "/nonexistent/x"])
        self.assertEqual(t.calls, [])
        self.assertEqual(rc2, 1)
        self.assertIn("not a file", so2)

    # 6
    def test_single_file_target(self):
        with NetworkTrap() as t:
            rc, so, se = run_cli([self.notes] + self.base)
        self.assertEqual(rc, 0, se + so)
        self.assertEqual(t.calls, [])
        self.assertIn("Summer2024!", so)

    # 7
    def test_json_export_schema(self):
        with NetworkTrap():
            rc, so, se = run_cli([self.root, "--no-inventory", "--no-pot",
                                  "--json", self._o("f.json")] + self.base)
        self.assertEqual(rc, 0, se + so)
        with open(self._o("f.json")) as fh:
            j = json.load(fh)
        self.assertEqual(j["schema_version"], 2)
        self.assertEqual(j["tool"], "secrethound")
        self.assertTrue(set(j["stats"]) >= {"scanned", "skipped", "mb", "elapsed"}, j["stats"])
        self.assertEqual(j["stats"]["scanned"], 3)
        self.assertGreaterEqual(len(j["findings"]), 10)
        for f in j["findings"]:
            self.assertEqual(set(f), {"category", "detail", "file", "hint", "line", "severity"})
        chains = j.get("chains", [])
        self.assertTrue(chains, "no chains exported")
        want = {"commands", "confidence", "count", "criticality", "lab_only", "label", "line",
                "proximity", "readiness", "rule", "score", "source", "summary"}
        for c in chains:
            self.assertEqual(set(c), want)
            for cmd in c["commands"]:
                ok, why = compliance.lint_command(cmd, tagged=c["lab_only"])
                self.assertTrue(ok, f"{c['rule']}: {why}: {cmd}")
        # the jdoe:Summer2024! cred in notes.txt yields the spray chain
        self.assertTrue(any(c["rule"] == "R1" for c in chains),
                        sorted({c["rule"] for c in chains}))

    # 8
    def test_help_and_missing_path(self):
        with NetworkTrap() as t:
            rc, so, _ = run_cli(["-h"])
            self.assertEqual(rc, 0)
            self.assertIn("USAGE", so)
            self.assertIn("OSCP NOTE", so)
            rc, so, _ = run_cli([])
            self.assertEqual(rc, 0)
            self.assertIn("USAGE", so)
            rc, so, _ = run_cli(["/nonexistent/zzz"])
            self.assertEqual(rc, 1)
            self.assertIn("[x] path not found", so)
        self.assertEqual(t.calls, [])

    # 9
    def test_banner_never_contaminates_stdout_or_exports(self):
        with NetworkTrap():
            rc, so, se = run_cli([self.root, "--no-inventory", "--no-pot",
                                  "--json", self._o("g.json")] + self.base,
                                 stdout_tty=True, stderr_tty=True)
        self.assertEqual(rc, 0, se + so)
        self.assertNotIn("H U N T", so)
        self.assertNotIn("H U N T", se)          # --json suppresses the banner
        with open(self._o("g.json"), "rb") as fh:
            raw = fh.read()
        self.assertEqual(raw[:1], b"{")
        json.loads(raw.decode("utf-8"))

    # 10
    def test_users_out_respected_and_no_repo_pollution(self):
        with NetworkTrap():
            rc, so, se = run_cli([self.root, "--no-inventory", "--no-pot"] + self.base)
        self.assertEqual(rc, 0, se + so)
        self.assertTrue(os.path.exists(self._o("users.txt")))
        for p, pre in self._pre.items():
            if not pre:
                self.assertFalse(os.path.exists(p), f"run wrote {p} despite --users-out")


if __name__ == "__main__":
    unittest.main()
