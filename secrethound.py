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
from core import correlate
from analyzers import (keyword, entropy, patterns, credpairs, encoded, files,
                       inspect, sqlite_triage, playbook, filters, notes, inventory)
from analyzers.ingest import run as ingest_run, Store, potfile

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
  --json FILE       also write findings + attack chains to FILE as JSON
  --hashes FILE     write crack-ready hashes to FILE + print hashcat commands
  --cap N           max findings shown per section (default 40)
  --src             also scan source code (noisy)
  --ascii           ASCII-only output (no box-drawing / unicode)
  --no-color        plain output (for piping / `script` logging)
  -q, --quiet       suppress banner + progress (stderr)

CORRELATION (on by default - all read-only / OSCP-exam-legal)
  --no-ingest       don't parse other tools' output (nmap/BloodHound/nxc.db/
                    ldapdomaindump/enum4linux/gobuster/secretsdump dumps)
  --no-correlate    don't chain findings into the ranked ATTACK PATH
  --no-notes        don't mine your notes for creds + resume points
  --no-inventory    don't read /etc/hosts + ~/.ssh for name<->IP resolution
  --pot FILE        extra hashcat/john potfile (repeatable); ~/.hashcat + ~/.john auto
  --no-pot          disable cracked-hash cross-reference
  --users-out FILE  write aggregated usernames for spraying (default users.txt)

SEVERITY
  [!!] CRITICAL  decoded credential, user+pass pair, default-pw hash -> act now
  [!]  HIGH      real secret value, crackable hash, private key, key file
  [~]  MEDIUM    probable hash/token to verify / backup / history
  [-]  LOW       weak high-entropy lead -> verify by hand
  [+]  INFO      interesting file located -> read it

WORKFLOW
  1. Point it at your whole engagement dir (loot + scans + notes):
       secrethound ./engagement --deep --json findings.json --hashes crack.txt
  2. Read the ATTACK PATH panel - the ranked BEST NEXT ACTION is your move.
  3. Then START HERE / CRED PAIRS / ENCODED. Decode any base64 hint.
  4. Crack hashes:    hashcat -m <mode> crack.txt rockyou.txt
  5. secrethound --inspect <file>   to read one file in depth.

OSCP NOTE
  Pure local file analysis. It reads loot, other tools' OUTPUT files, your notes,
  your ~/.hashcat|~/.john potfiles, /etc/hosts and ~/.ssh on YOUR Kali box. It
  never touches a target - no scanning, no connections, no exploitation - so it
  is OSCP/OSCP+ exam-compliant. Every suggested command is a manual, exam-legal
  technique, vetted against analyzers/compliance.py. Lines marked [LAB-ONLY]
  (Responder/relay) rely on spoofing and are NOT exam-legal - the tool never
  puts them in the ranked ATTACK PATH.
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
    # v3: ingestion + correlation (all read-only / exam-legal)
    ap.add_argument("--no-ingest", action="store_true", help="don't parse other tools' output")
    ap.add_argument("--no-correlate", action="store_true", help="don't run the attack-chain engine")
    ap.add_argument("--no-notes", action="store_true", help="don't mine notes for creds/resume points")
    ap.add_argument("--no-inventory", action="store_true", help="don't read /etc/hosts + ~/.ssh for name<->IP")
    ap.add_argument("--pot", action="append", metavar="FILE", help="extra hashcat/john potfile (repeatable)")
    ap.add_argument("--no-pot", action="store_true", help="disable potfile cracked-hash cross-ref")
    ap.add_argument("--users-out", metavar="FILE", default="users.txt", help="write aggregated usernames here")
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
    do_ingest = not args.no_ingest
    targets, ingest_targets, skipped = [], [], 0
    for path in raw:
        ext = os.path.splitext(path)[1].lower()
        if json_abs and os.path.abspath(path) == json_abs:
            skipped += 1
            continue
        if filters.is_secrethound_output(path):
            skipped += 1
            continue
        # ingest sees ALL files (tool output arrives with arbitrary names/exts)
        if do_ingest:
            ingest_targets.append(path)
        if ext in DB_EXT:
            targets.append(path)
            continue
        if not is_text_target(path, scan_src=args.src):
            skipped += 1
            continue
        if filters.is_noise_file(path) or filters.is_binary_ish(path):
            skipped += 1
            continue
        targets.append(path)

    # ── scan with progress ──
    store = Store()      # shared evidence spine; analyzers feed it for correlation
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
        keyword.analyze(path, report, store)
        patterns.analyze(path, report)
        if run_entropy and ext in ENTROPY_EXT:
            entropy.analyze(path, report, threshold=thr)
    if not args.quiet:
        ui.progress_done()

    scan_root = root if os.path.isdir(root) else (os.path.dirname(root) or ".")

    # ── v3: ingest other tools' output, notes, inventory, potfile, correlate ──
    claimed = set()
    if not args.no_inventory:
        inventory.load(report, store)          # name<->IP resolver first
    if do_ingest:
        if not args.quiet:
            sys.stderr.write(ui.c("gray", f"  correlating loot + tool output {ui.ell}\n"))
            sys.stderr.flush()
        claimed = ingest_run(ingest_targets, report, store, args)
    if not args.no_notes:
        for p in targets:
            base = os.path.basename(p).lower()
            ext = os.path.splitext(p)[1].lower()
            looks_notes = ext in (".md", ".markdown") or any(
                k in base for k in ("note", "cred", "loot", "password", "todo", "readme"))
            if looks_notes and os.path.abspath(p) not in claimed:
                notes.analyze(p, report, store)
    if not args.no_pot:
        potfile.correlate(report, store, args)

    files.analyze_tree(scan_root, report, skip_paths=claimed)

    chains = []
    if not args.no_correlate:
        chains = correlate.run(report, store, ui)

    # aggregated users.txt for spray commands
    users = store.users_txt()
    if users and args.users_out:
        try:
            with open(args.users_out, "w") as fh:
                fh.write("\n".join(users) + "\n")
        except OSError:
            pass

    report.set_stats(scanned=total, skipped=skipped,
                     mb=total_bytes / (1024 * 1024), elapsed=time.monotonic() - t0)

    # ── output ──
    print(report.dashboard())
    board = report.scoreboard(chains, store)
    if board:
        print()
        print(board)
    print()
    print(ui.legend())
    hero = report.hero()
    if hero:
        print()
        print(hero)
    ap_panel = report.attack_path(chains)
    if ap_panel:
        print()
        print(ap_panel)
    print(report.render())

    # NEXT STEPS playbook only when the correlator produced nothing (fallback)
    if not chains:
        playbook.emit(report, _collect_signals(report), ui)

    # ── crack-ready hashes (blanks + already-cracked excluded) ──
    if args.hashes and patterns.HASHES:
        cracked = store.cracked
        seen, n_cracked = {}, 0
        for mode, name, val, fp, ln in patterns.HASHES:
            if potfile.normalize(val) in cracked:
                n_cracked += 1
                continue
            seen.setdefault((mode, name), set()).add(val)
        allh = sorted({v for vs in seen.values() for v in vs})
        if allh:
            with open(args.hashes, "w") as fh:
                fh.write("\n".join(allh) + "\n")
            print(ui.c("bgreen", f"\n[+] crack-ready hashes -> {args.hashes}" +
                       (f"  ({n_cracked} already cracked, omitted)" if n_cracked else "")))
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
        report.to_json(args.json, chains=chains)
        print(ui.c("dim", f"\n[+] findings + chains + stats written to {args.json}\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
