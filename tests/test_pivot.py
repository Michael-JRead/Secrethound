"""Pivot / tunnel landing detectors: chisel (Go-timestamp anchored), ligolo-ng,
ssh -L/-R/-D, netsh portproxy (any arg order), socat. Pivots are mandatory
report content on the AD set; iter-309 fixed three FP classes (nginx/redis
'Listening on', unused ligolo regex, fixed-order netsh) and these tests pin
the anchors so the fixes cannot silently regress."""
import unittest

from tests._helpers import PIVOT_ALL, run_keyword, hint_names_banned_tool

_HINT_TOKENS = ("document in report", "proxychains", "ligolo", "cleanup", "attacker connects",
                "tunnel is up")


def piv(text, ext=".log", name="fixture"):
    r, s = run_keyword(text, ext, name)
    return r.cat("PIVOT"), [e for e in s.items if e.kind == "pivot_landed"]


class PivotDetectorTests(unittest.TestCase):
    # 1
    def test_chisel_server_requires_go_timestamp(self):
        f, ev = piv(PIVOT_ALL)
        x = [a for a in f if a["detail"].startswith("Chisel server")]
        self.assertEqual(len(x), 1)
        self.assertEqual((x[0]["severity"], x[0]["line"]), ("HIGH", 2))
        self.assertEqual(x[0]["detail"],
                         "Chisel server listening on http://0.0.0.0:8080 - pivot tunnel endpoint established")
        self.assertIn("chisel client <attacker>:<port> R:socks", x[0]["hint"])
        self.assertIn("proxychains nmap", x[0]["hint"])
        e = [e for e in ev if e.line == 2][0]
        self.assertEqual(e.meta, {"tool": "chisel", "role": "server", "endpoint": "http://0.0.0.0:8080"})

    # 2
    def test_chisel_client_connected_dedupes_per_file(self):
        f, ev = piv("2024/01/15 15:15:23 client: Connected (Latency 12ms)\n" * 3)
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["severity"], f[0]["line"]), ("HIGH", 1))
        self.assertEqual(f[0]["detail"], "Chisel client CONNECTED - reverse tunnel active into internal network")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0].meta["role"], ev[0].meta["status"]), ("client", "connected"))
        f2, _ = piv("2024/01/15 15:15:23 client: session#1: Connected\n")
        self.assertEqual(len(f2), 1)

    # 3
    def test_ligolo_proxy_listener(self):
        f, ev = piv(PIVOT_ALL)
        x = [a for a in f if a["detail"].startswith("Ligolo-ng proxy")]
        self.assertEqual(len(x), 1)
        self.assertEqual(x[0]["detail"],
                         "Ligolo-ng proxy listening on 0.0.0.0:11601 - pivot tunnel endpoint established")
        self.assertEqual((x[0]["severity"], x[0]["line"]), ("HIGH", 4))
        self.assertIn("./ligolo-agent -connect <attacker>:11601 -ignore-cert", x[0]["hint"])
        e = [e for e in ev if e.line == 4][0]
        self.assertEqual(e.meta, {"tool": "ligolo-ng", "role": "proxy_listener", "endpoint": "0.0.0.0:11601"})
        f2, ev2 = piv("Listening on 0.0.0.0:11601\n")          # no INFO[n] prefix
        self.assertEqual((f2, ev2), ([], []))

    # 4
    def test_ligolo_agent_joined(self):
        f, ev = piv(PIVOT_ALL)
        x = [a for a in f if a["detail"].startswith("Ligolo-ng agent")]
        self.assertEqual(len(x), 1)
        self.assertEqual(x[0]["detail"],
                         "Ligolo-ng agent JOINED: WEB01.corp.local from 10.10.14.5:44210 - pivot tunnel active")
        self.assertEqual((x[0]["severity"], x[0]["line"]), ("HIGH", 5))
        self.assertIn("start --tun ligolo", x[0]["hint"])
        e = [e for e in ev if e.line == 5][0]
        self.assertEqual(e.host, "web01.corp.local")             # Store.add canonicalises to lowercase
        self.assertEqual(e.meta["agent_remote"], "10.10.14.5:44210")
        self.assertEqual(e.meta["role"], "proxy")

    # 5
    def test_ssh_local_reverse_dynamic(self):
        f, ev = piv(PIVOT_ALL)
        ssh = {a["line"]: a for a in f if a["detail"].startswith("SSH -")}
        self.assertEqual(sorted(ssh), [6, 7, 8])
        self.assertTrue(all(a["severity"] == "MEDIUM" for a in ssh.values()))
        self.assertEqual(ssh[6]["detail"],
                         "SSH -L local-forward: 8080:10.20.30.40:80 - port-forward tunnel command captured")
        self.assertEqual(ssh[7]["detail"],
                         "SSH -R reverse-forward: 4444:127.0.0.1:4444 - port-forward tunnel command captured")
        self.assertEqual(ssh[8]["detail"], "SSH -D SOCKS-proxy: 9050 - port-forward tunnel command captured")
        got = [(e.meta["flag"], e.meta["mode"], e.meta["spec"]) for e in ev if e.meta["tool"] == "ssh"]
        self.assertEqual(got, [("-L", "local-forward", "8080:10.20.30.40:80"),
                               ("-R", "reverse-forward", "4444:127.0.0.1:4444"),
                               ("-D", "SOCKS-proxy", "9050")])
        f2, ev2 = piv("ssh -N -f -L 8080:10.20.30.40:80 user@jumphost\n")    # extra flags before -L
        self.assertEqual(len(f2), 1)
        self.assertEqual(ev2[0].meta["spec"], "8080:10.20.30.40:80")

    # 6
    def test_netsh_portproxy_any_arg_order_and_dedupe(self):
        text = ("netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 "
                "connectport=445 connectaddress=10.20.30.40\n"
                "netsh interface portproxy add v4tov4 connectaddress=10.20.30.40 listenport=8080 "
                "connectport=445 listenaddress=0.0.0.0\n")
        f, ev = piv(text)
        self.assertEqual(len(f), 1)                              # same signature -> one finding
        self.assertEqual(f[0]["severity"], "HIGH")
        self.assertEqual(f[0]["detail"], "netsh portproxy ADD: listen :8080 -> 10.20.30.40:445 - Windows LOLBAS pivot")
        self.assertIn("netsh interface portproxy reset", f[0]["hint"])
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].meta, {"tool": "netsh_portproxy", "listen_port": "8080",
                                      "connect_addr": "10.20.30.40", "connect_port": "445"})
        f2, _ = piv("netsh interface portproxy add v4tov4 listenport=8080\n")   # missing connect fields
        self.assertEqual(f2, [])

    # 7
    def test_socat_listen_forward(self):
        f, _ = piv(PIVOT_ALL)
        x = [a for a in f if a["line"] == 10]
        self.assertEqual(len(x), 1)
        self.assertEqual(x[0]["severity"], "HIGH")
        self.assertEqual(x[0]["detail"], "socat TCP-LISTEN pivot: :8080 -> 10.20.30.40:445 - Linux LOLBAS forward")
        f2, ev2 = piv("socat TCP-LISTEN:1234,fork,reuseaddr TCP:internal:22\n")
        self.assertEqual(len(f2), 1)
        self.assertEqual(f2[0]["detail"], "socat TCP-LISTEN pivot: :1234 -> internal:22 - Linux LOLBAS forward")
        self.assertEqual(ev2[0].meta, {"tool": "socat", "listen_port": "1234", "dest_addr": "internal",
                                       "dest_port": "22"})

    # 8  (iter-309 FP guard)
    def test_no_timestamp_service_logs_do_not_fire(self):
        f, ev = piv("server: Listening on http://0.0.0.0:80\n"
                    "client: Connected\n"
                    "Listening on 0.0.0.0:11601\n"
                    "[notice] nginx/1.18.0 server: Listening on http://127.0.0.1:8080\n"
                    "redis client: Connected (Latency 2ms)\n")
        self.assertEqual((f, ev), ([], []))

    # 9
    def test_pivot_doc_gate(self):
        f, _ = piv(PIVOT_ALL, ".md")
        self.assertEqual(f, [])
        f, _ = piv(PIVOT_ALL, ".txt", name="pivoting-cheatsheet")    # doc-ish filename
        self.assertEqual(f, [])

    # 10
    def test_pivot_totals_and_tool_set(self):
        f, ev = piv(PIVOT_ALL)
        self.assertEqual(len(f), 9)
        self.assertEqual(len(ev), 9)
        self.assertEqual({e.meta["tool"] for e in ev},
                         {"chisel", "ligolo-ng", "ssh", "netsh_portproxy", "socat"})
        for a in f:
            with self.subTest(detail=a["detail"][:50]):
                self.assertTrue(any(t in a["hint"] for t in _HINT_TOKENS), a["hint"])
                self.assertFalse(hint_names_banned_tool(a["hint"]), a["hint"])


if __name__ == "__main__":
    unittest.main()
