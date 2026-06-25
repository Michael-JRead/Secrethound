#!/usr/bin/env python3
"""secrethound - offline credential & secret analyzer for OSCP+ loot.

Local-analysis only: reads files you already hold. No network, no scanning,
no exploitation. OSCP/OSCP+ exam-compliant. The tool POINTS; you ACT.
Empty != clean - also read configs by hand for unlabeled secrets."""
import os
import sys
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.report import Report
from core.ui import UI
from analyzers import (keyword, entropy, patterns, credpairs, encoded, files,
                       inspect, sqlite_triage, playbook, filters)

VERSION = "2.0"
TEXT_EXT = {".ini", ".conf", ".cnf", ".cfg", ".env", ".yml", ".yaml", ".json", ".xml",
            ".toml", ".properties", ".txt", ".js", ".sql", ".bak", ".old", ".log", ".md",
            ".netrc", ".htpasswd", ".pem", ".key", ".config", ".tmpl", ".template",
            ".ps1", ".psd1", ".reg", ".ovpn", ".kdbx", ".php", ".inc", ".tfstate",
            ".tfvars", ".sh", ".bat", ".cmd", ""}
SRC_EXT = {".js", ".pl", ".ps1", ".py", ".php", ".rb", ".java", ".go", ".cs", ".sh"}
DB_EXT = {".sqlite", ".sqlite3", ".db", ".db3"}
MAX_BYTES = 5 * 1024 * 1024
ENTROPY_EXT = {".ini", ".conf", ".cnf", ".cfg", ".env", ".yml", ".yaml", ".json",
               ".xml", ".toml", ".properties", ".txt", ".config", ".tmpl", ".template",
               ".log", ""}

HELP = r"""
secrethound - offline secret/credential analyzer for OSCP+ loot

USAGE
  secrethound <PATH> [options]
  secrethound --inspect <FILE>
  secrethound -h

OPTIONS
  --deep            run ALL analyzers including entropy (more coverage)
  --inspect FILE    deep-dive ONE file: every secret-bearing line, numbered
  --entropy         entropy analyzer only (catches UNLABELED secrets)
  --entropy-low     lower entropy threshold to 3.5 (noisier, catches more)
  --all             show every finding incl. LOW-confidence entropy (no collapse)
  --group dir       group the per-directory dashboard by machine (default on for trees)
  --json FILE       also write findings to FILE as JSON (for your report)
  --hashes FILE     write crack-ready hashes to FILE + print hashcat commands
  --cap N           max findings shown per section (default 40)
  --src             also scan source code (noisy)
  --ascii           ASCII-only output (no box-drawing / unicode)
  --no-color        plain output (for piping / `script` logging)
  -q, --quiet       suppress banner + progress (stderr)

SEVERITY
  [!!] CRITICAL  decoded credential, user+pass pair, default-pw hash -> act now
  [!]  HIGH      real secret value, crackable hash, private key, key file
  [~]  MEDIUM    probable hash/token to verify / backup / history
  [-]  LOW       weak high-entropy lead -> verify by hand
  [+]  INFO      interesting file located -> read it

WORKFLOW
  1. secrethound ./loot --deep --json findings.json --hashes crack.txt
  2. Act on START HERE, then CRED PAIRS + ENCODED. Decode any base64 hint.
  3. Confirm a cred:  netexec smb <dc> -u <user> -p <pass> -k
  4. Crack hashes:    hashcat -m <mode> crack.txt rockyou.txt
  5. secrethound --inspect <file>   to read one file in depth.

OSCP NOTE
  Pure local file analysis. No scanning/exploitation/target traffic = compliant.
  Suggested commands are manual, exam-legal techniques. Lines marked
  [LAB-ONLY] (Responder/relay) rely on spoofing and are NOT exam-legal.
"""


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if not filters.should_skip_dir(d, os.path.join(dirpath, d))]
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


def _collect_signals(report):
    """build the set of signal names playbook.emit() understands."""
    sig = set()
    for f in report.findings:
        sig.add(f["category"])
        # extract the detector name from "name: value" / "name (..): value"
        d = f["detail"]
        head = d.split(":", 1)[0].split("(", 1)[0].strip()
        if head:
            sig.add(head)
    return sig


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("path", nargs="?")
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--entropy", action="store_true")
    ap.add_argument("--entropy-low", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--group", choices=["cat", "dir"], default="cat")
    ap.add_argument("--inspect", metavar="FILE")
    ap.add_argument("--hashes", metavar="FILE")
    ap.add_argument("--json")
    ap.add_argument("--cap", type=int, default=40)
    ap.add_argument("--ascii", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--src", action="store_true", help="also scan source code (noisy)")
    args = ap.parse_args()

    use_color = not args.no_color
    ui = UI(use_color=use_color, ascii_only=args.ascii)

    if args.inspect:
        if not os.path.isfile(args.inspect):
            print(f"[x] not a file: {args.inspect}")
            return 1
        inspect.deep_dive(args.inspect, use_color=use_color)
        return 0

    if args.help or not args.path:
        print(HELP)
        return 0
    if not os.path.exists(args.path):
        print(f"[x] path not found: {args.path}\n    try: secrethound -h")
        return 1

    root = args.path
    report_root = root if os.path.isdir(root) else (os.path.dirname(root) or ".")
    report = Report(use_color=use_color, cap_per_section=args.cap, root=report_root,
                    show_low=args.all, group_by_dir=(args.group == "dir"),
                    ascii_only=args.ascii)
    thr = 3.5 if args.entropy_low else 4.0
    run_entropy = args.deep or args.entropy or args.entropy_low
    patterns.HASHES.clear()

    # ── banner + legend (stderr so stdout stays clean) ──
    if not args.quiet:
        sys.stderr.write(ui.banner(VERSION) + "\n\n")
        sys.stderr.write(ui.c("gray", f"  scanning {root}  ({'deep' if run_entropy else 'standard'} mode)\n\n"))
        sys.stderr.flush()

    # ── enumerate, skipping self-output + noise ──
    json_abs = os.path.abspath(args.json) if args.json else None
    raw = [root] if os.path.isfile(root) else list(iter_files(root))
    targets, skipped = [], 0
    for path in raw:
        ext = os.path.splitext(path)[1].lower()
        if ext in DB_EXT:
            targets.append(path)
            continue
        if not is_text_target(path, scan_src=args.src):
            skipped += 1
            continue
        if json_abs and os.path.abspath(path) == json_abs:
            skipped += 1
            continue
        if filters.is_noise_file(path) or filters.is_secrethound_output(path):
            skipped += 1
            continue
        targets.append(path)

    # ── scan with progress ──
    t0 = time.monotonic()
    total = len(targets)
    total_bytes = 0
    for i, path in enumerate(targets, 1):
        if not args.quiet:
            ui.progress(i, total, current=os.path.relpath(path, root) if os.path.isdir(root) else path)
        try:
            total_bytes += os.path.getsize(path)
        except OSError:
            pass
        ext = os.path.splitext(path)[1].lower()
        if ext in DB_EXT:
            sqlite_triage.analyze_db(path, report)
            continue
        credpairs.analyze(path, report)
        encoded.analyze(path, report)
        keyword.analyze(path, report)
        patterns.analyze(path, report)
        if run_entropy and ext in ENTROPY_EXT:
            entropy.analyze(path, report, threshold=thr)
    if not args.quiet:
        ui.progress_done()

    files.analyze_tree(root if os.path.isdir(root) else (os.path.dirname(root) or "."), report)

    report.set_stats(scanned=total, skipped=skipped,
                     mb=total_bytes / (1024 * 1024), elapsed=time.monotonic() - t0)

    # ── output ──
    print(report.dashboard())
    print()
    print(ui.legend())
    hero = report.hero()
    if hero:
        print()
        print(hero)
    print(report.render())

    playbook.emit(report, _collect_signals(report), ui)

    # ── crack-ready hashes (blanks already excluded upstream) ──
    if args.hashes and patterns.HASHES:
        seen = {}
        for mode, name, val, fp, ln in patterns.HASHES:
            seen.setdefault((mode, name), set()).add(val)
        allh = sorted({v for vs in seen.values() for v in vs})
        with open(args.hashes, "w") as fh:
            fh.write("\n".join(allh) + "\n")
        print(ui.c("bgreen", f"\n[+] crack-ready hashes -> {args.hashes}"))
        for (mode, name), vs in sorted(seen.items()):
            if not mode or mode == "0":
                print(ui.c("yellow", f"    {name} (x{len(vs)}):  hashid one first, then hashcat -m <mode>"))
            else:
                print(ui.c("yellow", f"    {name} (x{len(vs)}):  hashcat -m {mode} {args.hashes} rockyou.txt"))

    a = ui.arrow2
    print()
    print(ui.rule(f"act on START HERE {a} CRED PAIRS/ENCODED {a} confirm with netexec {a} crack hashes", color="cyan"))
    print(ui.rule("empty != clean: also read configs by hand for unlabeled secrets", color="cyan"))

    if args.json:
        report.to_json(args.json)
        print(ui.c("dim", f"\n[+] findings (with stats) written to {args.json}\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
