#!/usr/bin/env python3
"""secrethound - offline credential & secret analyzer for OSCP loot.
Local-analysis only: reads files you already hold. No network, no scanning,
no exploitation. OSCP-exam compliant. The tool POINTS; you ACT. Empty != clean."""
import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.report import Report
from analyzers import keyword, entropy, patterns, credpairs, encoded, files, inspect, sqlite_triage, playbook

SKIP_DIRS = {"site-packages", "node_modules", "vendor", "__pycache__", ".git",
             "dist-info", "templates", "languages", "locale"}
TEXT_EXT = {".ini", ".conf", ".cnf", ".cfg", ".env", ".yml", ".yaml", ".json", ".xml",
            ".toml", ".properties", ".txt", ".js", ".sql", ".bak", ".old", ".log", ".md", ".netrc", ".htpasswd",
            ".pem", ".key", ".config", ".tmpl", ".template", ""}
SRC_EXT = {".js", ".pl", ".ps1"}
DB_EXT = {".sqlite", ".sqlite3", ".db", ".db3"}
MAX_BYTES = 5 * 1024 * 1024
# entropy scanning is ONLY meaningful on these — NEVER on .pem/.crt/.key (entropy by definition)
ENTROPY_EXT = {".ini", ".conf", ".cnf", ".cfg", ".env", ".yml", ".yaml", ".json",
               ".xml", ".toml", ".properties", ".txt", ".config", ".tmpl", ".template", ""}

HELP = r"""
secrethound - offline secret/credential analyzer for OSCP loot

USAGE
  secrethound <PATH> [options]
  secrethound --inspect <FILE>
  secrethound -h

OPTIONS
  --deep            run ALL analyzers including entropy (more coverage)
  --inspect FILE    deep-dive ONE file: every secret-bearing line, numbered
  --entropy         entropy analyzer only (catches UNLABELED secrets)
  --entropy-low     lower entropy threshold to 3.0 (noisier, catches more)
  --json FILE       also write findings to FILE as JSON (for your report)
  --cap N           max findings shown per section (default 40)
  --no-color        plain output (for piping / `script` logging)

SEVERITY
  [!!] CRITICAL  decoded credential, or user+pass pair in one file -> act now
  [!]  HIGH      real secret value, known hash, private key, key-bearing file
  [~]  MEDIUM    high-entropy token / reference / backup / history -> verify
  [+]  INFO      config file located -> read it

WORKFLOW
  1. secrethound ./loot --deep --json findings.json
  2. Read CRED PAIRS + ENCODED first. Decode any base64 hint.
  3. Confirm a cred:  netexec smb <dc> -u <user> -p <pass> -k
  4. Verify a key:    openssl rsa -in <file> -noout 2>/dev/null && echo VALID
  5. secrethound --inspect <file>   to read one file in depth.

OSCP NOTE
  Pure local file analysis. No scanning, no exploitation, no target traffic.
  Compliant. The tool only points - YOU read the file and act on it.
"""


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def is_text_target(path, scan_src=False):
    ext = os.path.splitext(path)[1].lower()
    allowed = TEXT_EXT | SRC_EXT if scan_src else TEXT_EXT
    if ext not in allowed:
        return False
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return False
    except OSError:
        return False
    return True


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("path", nargs="?")
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--entropy", action="store_true")
    ap.add_argument("--entropy-low", action="store_true")
    ap.add_argument("--inspect", metavar="FILE")
    ap.add_argument("--hashes", metavar="FILE")
    ap.add_argument("--json")
    ap.add_argument("--cap", type=int, default=40)
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--src", action="store_true", help="also scan source code (noisy)")
    args = ap.parse_args()

    if args.inspect:
        if not os.path.isfile(args.inspect):
            print(f"[x] not a file: {args.inspect}")
            return 1
        inspect.deep_dive(args.inspect, use_color=not args.no_color)
        return 0

    if args.help or not args.path:
        print(HELP)
        return 0
    if not os.path.exists(args.path):
        print(f"[x] path not found: {args.path}\n    try: secrethound -h")
        return 1

    report = Report(use_color=not args.no_color, cap_per_section=args.cap)
    thr = 3.5 if args.entropy_low else 4.0
    run_entropy = args.deep or args.entropy or args.entropy_low
    patterns.HASHES.clear()
    root = args.path
    targets = [root] if os.path.isfile(root) else list(iter_files(root))

    for path in targets:
        if os.path.splitext(path)[1].lower() in DB_EXT:
            sqlite_triage.analyze_db(path, report)
            continue
        if not is_text_target(path, scan_src=args.src):
            continue
        credpairs.analyze(path, report)
        encoded.analyze(path, report)
        keyword.analyze(path, report)
        patterns.analyze(path, report)
        if run_entropy and os.path.splitext(path)[1].lower() in ENTROPY_EXT:
            entropy.analyze(path, report, threshold=thr)

    if os.path.isdir(root):
        files.analyze_tree(root, report)
    else:
        files.analyze_tree(os.path.dirname(root) or ".", report)

    c = report._c
    print(c("green", "╔══════════════════════════════════════════════╗"))
    print(c("green", f"║  secrethound → {root[:30]:<30} ║"))
    print(c("green", "╚══════════════════════════════════════════════╝"))
    print("  " + report.summary())
    top=None
    for cat in ["CRED PAIRS","ENCODED/DECODED","SQLITE","GPP cpassword","ASSIGNED SECRETS","PASSWORD HASHES"]:
        hits=[f for f in report.findings if f["category"]==cat and f["severity"] in ("CRITICAL","HIGH")]
        if hits:
            h=hits[0]; loc=h["file"]+(f":{h['line']}" if h["line"] else ""); top=f"START HERE -> {cat}: {loc}"; break
    if top:
        print(c("red", f"  |- {top}"))
        print(c("red", "  |- act on CRITICAL/HIGH first; see NEXT STEPS for the command"))
    print(report.render())
    print(c("cyan", "\n── CRED PAIRS/ENCODED first → confirm with netexec → verify keys with openssl ──"))
    print(c("cyan", "── empty != clean: also read configs by hand for unlabeled secrets ──"))
    if args.hashes and patterns.HASHES:
        seen = {}
        for mode, name, val, fp, ln in patterns.HASHES:
            seen.setdefault((mode, name), set()).add(val)
        allh = sorted({v for vs in seen.values() for v in vs})
        with open(args.hashes, "w") as fh: fh.write("\n".join(allh) + "\n")
        print(c("green", f"\n[+] crack-ready hashes -> {args.hashes}"))
        for (mode, name), vs in sorted(seen.items()):
            print(c("yellow", f"    {name} (x{len(vs)}):  hashcat -m {mode} {args.hashes} rockyou.txt"))

    if args.json:
        report.to_json(args.json)
        print(c("dim", f"\n[+] findings written to {args.json}\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
