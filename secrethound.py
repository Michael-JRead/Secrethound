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
                       inspect, sqlite_triage, playbook, filters, notes, inventory,
                       configs)
from analyzers.ingest import run as ingest_run, Store, potfile

VERSION = "2.0"
TEXT_EXT = {".ini", ".conf", ".cnf", ".cfg", ".env", ".yml", ".yaml", ".json", ".xml",
            ".toml", ".properties", ".txt", ".js", ".sql", ".bak", ".old", ".log", ".md",
            ".netrc", ".htpasswd", ".pem", ".key", ".config", ".tmpl", ".template",
            ".ps1", ".psd1", ".reg", ".ovpn", ".kdbx", ".php", ".inc", ".tfstate",
            ".tfvars", ".sh", ".bat", ".cmd", ".hash", ".hashes", ".pot", ".potfile",
            ".lst", ".csv", ".tsv", ".ldif", ".ldap", ".pcap", ".eml", ".html", ".htm",
            ".rtf",
            # iter-12: compressed rotated logs - filters.read_text() handles
            # transparent decompression so they look like text to analyzers.
            ".gz", ".bz2", ".xz", ".tgz",
            # iter-12: NDJSON / JSONL credential dumps (Bloodhound, secretsdump
            # JSON, kubectl get -o json | jq -c)
            ".ndjson", ".jsonl",
            # iter-28: systemd unit files (Environment= directives carry
            # plaintext creds on service-managed boxes)
            ".service", ".socket", ".timer", ".target", ".mount", ".path",
            # iter-86: RDP saved sessions (.rdp = plaintext KV-style file,
            # .rdg = RDCMan XML). Both carry the RDP username + target host
            # + a DPAPI-encrypted password blob the operator can flag for
            # DPAPI decryption via R-DPAPI later.
            ".rdp", ".rdg",
            ""}
SRC_EXT = {".js", ".pl", ".ps1", ".py", ".php", ".rb", ".java", ".go", ".cs", ".sh"}
DB_EXT = {".sqlite", ".sqlite3", ".db", ".db3"}
# iter-12: was 5 MB. Raised to 64 MB so secretsdump / BloodHound users.json /
# rotated nginx logs aren't silently skipped. Anything larger is reported as
# INFO so the operator knows to re-run or inspect by hand.
MAX_BYTES = 64 * 1024 * 1024
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
  --html FILE       self-contained HTML report (KPI + scoreboard + chains + tables)
  --csv FILE        export CRED PAIRS / hashes / secrets to CSV for report appendix
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
    # iter-15: sort dirnames and filenames so the entire pipeline is
    # deterministic. os.walk() backs onto os.scandir() / readdir(), which
    # POSIX leaves unordered (ext4/xfs = hash-bucket, tmpfs = insertion,
    # NTFS = sorted). Two runs against an identical loot tree on different
    # filesystems otherwise produce different src/line attribution in the
    # ATTACK PATH / JSON / HTML exports.
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if not filters.should_skip_dir(d, os.path.join(dirpath, d)))
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def is_text_target(path, scan_src=False, oversized=None):
    """iter-12: oversized=set() collects paths that exceeded MAX_BYTES so the
    main loop can emit an INFO finding (silent skip = silent miss).
    iter-32: also scan named Python/Ruby config files even without --scan-src.
    settings.py / config.py / secrets.py / local_settings.py / production.py
    consistently carry framework SECRET_KEY + DATABASES creds on OSCP+ Python
    boxes; scanning ALL .py by default is too noisy but scanning THESE by
    name is high-signal."""
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path).lower()
    _PY_CONFIG_NAMES = {
        "settings.py", "config.py", "secrets.py", "local_settings.py",
        "production.py", "prod.py", "dev.py", "development.py",
        "database.py", "db.py", "application.py",
    }
    is_py_config = (base in _PY_CONFIG_NAMES
                    or base.endswith(("_config.py", "_settings.py",
                                       "_secrets.py")))
    allowed = TEXT_EXT | SRC_EXT if scan_src else TEXT_EXT
    if ext not in allowed and not is_py_config:
        return False
    try:
        sz = os.path.getsize(path)
        if sz > MAX_BYTES:
            if oversized is not None:
                oversized.add((path, sz))
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
    ap.add_argument("--html", metavar="FILE",
                    help="write a self-contained HTML report (KPIs + scoreboard + chains + per-cat tables)")
    ap.add_argument("--csv", metavar="FILE",
                    help="write CRED PAIRS + hashes + secrets as CSV for the report appendix")
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
    oversized = set()  # iter-12: surface skipped-due-to-size
    targets, ingest_targets, magic_targets, skipped = [], [], [], 0
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
        # iter-8: binary-magic scan sees ALL non-output files (.kdbx/.pfx/.kirbi
        # /.ccache/lsass.dmp/ESEDB carry concrete loot regardless of extension).
        magic_targets.append(path)
        if ext in DB_EXT:
            targets.append(path)
            continue
        if not is_text_target(path, scan_src=args.src, oversized=oversized):
            skipped += 1
            continue
        # iter-12: compressed loot bypasses is_binary_ish (gzip bytes look
        # random by definition); the decompression pre-pass below routes
        # them through the same per-line analyzers.
        is_compressed = ext in (".gz", ".bz2", ".xz", ".tgz")
        if filters.is_noise_file(path) or (not is_compressed and filters.is_binary_ish(path)):
            skipped += 1
            continue
        targets.append(path)
    # iter-12: tell the operator about oversized skips so they can re-run by hand
    for path, sz in oversized:
        report.add("INFO", "INTERESTING FILES", path, None,
                   f"file too large for scan ({sz // (1024 * 1024)} MB > {MAX_BYTES // (1024 * 1024)} MB cap)",
                   hint=f"inspect by hand: head -c 5M '{path}' | secrethound /dev/stdin   "
                        "(or split + scan; raise MAX_BYTES if you trust the source)")

    # ── scan with progress ──
    store = Store()      # shared evidence spine; analyzers feed it for correlation
    t0 = time.monotonic()
    total = len(targets)
    total_bytes = 0
    # iter-12: transparent decompression. For .gz/.bz2/.xz files, expand
    # ONCE into a session tempdir + pass the decompressed path to analyzers.
    # Cleaner than threading a `read_text()` helper through every analyzer.
    import tempfile, atexit, shutil
    compressed_tmpdir = None
    decompress_map = {}        # compressed-path -> decompressed-tmp-path
    for path in targets:
        ext = os.path.splitext(path)[1].lower()
        if ext in (".gz", ".bz2", ".xz", ".tgz"):
            text = filters.read_text(path, max_bytes=MAX_BYTES)
            if text:
                if compressed_tmpdir is None:
                    compressed_tmpdir = tempfile.mkdtemp(prefix="secrethound-decompressed-")
                    atexit.register(lambda: shutil.rmtree(compressed_tmpdir, ignore_errors=True))
                # mirror filename without the compression extension
                base = os.path.basename(path)
                for sfx in (".gz", ".bz2", ".xz", ".tgz"):
                    if base.lower().endswith(sfx):
                        base = base[:-len(sfx)]
                        break
                # ensure unique name
                tmp = os.path.join(compressed_tmpdir, f"{len(decompress_map)}_{base}")
                try:
                    with open(tmp, "w", encoding="utf-8", errors="replace") as fh:
                        fh.write(text)
                    decompress_map[path] = tmp
                except OSError:
                    pass

    # reverse map: decompressed-tmp-path -> original compressed-path
    tmp_to_orig = {tmp: orig for orig, tmp in decompress_map.items()}
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
        # iter-12: route compressed loot through the decompressed mirror so
        # per-line analyzers see plain text. We rewrite finding paths AFTER
        # the scan to point back at the original .gz so the operator can find
        # the source.
        scan_path = decompress_map.get(path, path)
        credpairs.analyze(scan_path, report)
        encoded.analyze(scan_path, report)
        keyword.analyze(scan_path, report, store)
        patterns.analyze(scan_path, report, store)
        configs.analyze(scan_path, report, store)
        if run_entropy and ext in ENTROPY_EXT:
            entropy.analyze(scan_path, report, threshold=thr)
    # iter-12: rewrite tmp paths in findings + store Evidence back to the
    # compressed original so the operator can find the source.
    if tmp_to_orig:
        for f in report.findings:
            orig = tmp_to_orig.get(f["file"])
            if orig:
                f["file"] = orig
        # also rewrite Evidence sources in the shared store
        for ev in store.items:
            orig = tmp_to_orig.get(ev.source)
            if orig:
                ev.source = orig
    if not args.quiet:
        ui.progress_done()

    # ── binary-magic loot scan on EVERY non-output file (.kdbx/.pfx/.kirbi/
    # .ccache/lsass.dmp/ESEDB carry concrete loot regardless of extension). ──
    for path in magic_targets:
        try:
            configs.scan_magic(path, report, store)
        except Exception:
            continue

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
        # iter-12: users.txt is for spraying - not a secret per se, but on a
        # multi-user box it's still a sensitive list. Use 0644 (the operator
        # may pipe this to other tools); but ensure it's owned by the user.
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
            # iter-12: 0600 perms on the hashes file (it's a cracking target,
            # often contains user-bound hashes that leak the principal too).
            from core.report import _write_secure
            _write_secure(args.hashes, "\n".join(allh) + "\n")
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
    if args.html:
        try:
            from core import html_report
            html_report.write_html(report, chains, store, args.html)
            print(ui.c("dim", f"[+] HTML report written to {args.html}\n"))
        except Exception as e:
            print(ui.c("red", f"[x] HTML export failed: {e}\n"))
    if args.csv:
        try:
            from core import html_report
            html_report.write_csv_creds(report, store, args.csv)
            print(ui.c("dim", f"[+] CSV creds export written to {args.csv}\n"))
        except Exception as e:
            print(ui.c("red", f"[x] CSV export failed: {e}\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
