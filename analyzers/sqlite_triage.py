"""sqlite_triage.py - opens .sqlite/.db READ-ONLY, surfaces credential columns + rows."""
import sqlite3, os, re
CRED_COL = re.compile(r'(?i)(pass|pwd|secret|hash|token|cred|api[_-]?key|salt)')
USER_COL = re.compile(r'(?i)(user|login|name|email|account|uid)')

def analyze_db(path, report, max_rows=3):
    try:
        con = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]
    except Exception as e:
        report.add("INFO", "SQLITE", path, None, f"could not open as sqlite ({e})"); return
    if not tables: return
    found = False
    for t in tables:
        try:
            cur.execute(f'PRAGMA table_info("{t}");')
            cols = [r[1] for r in cur.fetchall()]
        except Exception: continue
        cred_cols = [c for c in cols if CRED_COL.search(c)]
        user_cols = [c for c in cols if USER_COL.search(c)]
        if cred_cols:
            found = True
            want = []
            for c in user_cols[:2] + cred_cols[:3]:
                if c not in want: want.append(c)
            collist = ", ".join(want)
            collist_q = ", ".join(f'"{c}"' for c in want)
            report.add("CRITICAL", "SQLITE", path, None,
                       f'table "{t}" has credential columns: {", ".join(cred_cols)}',
                       f'sqlite3 {path} "SELECT {collist} FROM {t};"')
            try:
                cur.execute(f'SELECT {collist_q} FROM "{t}" LIMIT {max_rows};')
                for row in cur.fetchall():
                    report.add("HIGH", "SQLITE", path, None,
                               f'  {t}: ' + " | ".join(str(v)[:50] for v in row))
            except Exception: pass
        elif user_cols and len(cols) <= 30:
            report.add("MEDIUM", "SQLITE", path, None,
                       f'table "{t}" has user columns: {", ".join(user_cols)} (no cred col seen)')
    if not found and tables:
        report.add("INFO", "SQLITE", path, None,
                   f'{len(tables)} tables, no obvious cred columns: {", ".join(tables[:8])}')
    con.close()
