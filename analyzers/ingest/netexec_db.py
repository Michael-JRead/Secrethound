"""netexec_db.py - read netexec/crackmapexec workspace SQLite DBs (read-only).

These hold creds the operator ALREADY validated against targets - the highest-
trust evidence there is. Opened immutable so we never touch the live DB.
"""
import os
import sqlite3
from analyzers import patterns, filters
from analyzers.ingest.evidence import Evidence

_NXC_NAMES = {"smb.db", "ad.db", "mssql.db", "ldap.db", "winrm.db", "ssh.db",
              "rdp.db", "ftp.db", "wmi.db"}


def detect(path, head):
    if not head.startswith("SQLite format 3"):
        return False
    low = path.lower().replace("\\", "/")
    return (os.path.basename(low) in _NXC_NAMES
            or "/.nxc/" in low or "/.cme/" in low or "/workspaces/" in low)


def _open(path):
    return sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro&immutable=1", uri=True)


def _cols(cur, table):
    try:
        cur.execute(f'PRAGMA table_info("{table}")')
        return [r[1].lower() for r in cur.fetchall()]
    except sqlite3.Error:
        return []


def parse(path, store, report):
    try:
        con = _open(path)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
    except sqlite3.Error:
        return 0
    n = 0
    # hosts -> learn name<->ip + DC flag
    for t in tables:
        if t.lower() not in ("hosts", "computers"):
            continue
        cols = _cols(cur, t)
        try:
            cur.execute(f'SELECT * FROM "{t}"')
            rows = cur.fetchall()
        except sqlite3.Error:
            continue
        for row in rows:
            d = dict(zip(cols, row))
            ip = str(d.get("ip") or d.get("host") or "")
            name = str(d.get("hostname") or d.get("name") or "")
            store.learn_host(ip=ip, names=[name] if name else [])
            is_dc = str(d.get("dc") or d.get("is_dc") or "0") in ("1", "True", "true")
            if ip or name:
                store.add(Evidence(kind="host", host=ip or name,
                                   fact="dc" if is_dc else "", source=path))
    # users/creds -> validated creds (gold)
    for t in tables:
        if t.lower() not in ("users", "creds", "credentials"):
            continue
        cols = _cols(cur, t)
        try:
            cur.execute(f'SELECT * FROM "{t}"')
            rows = cur.fetchall()
        except sqlite3.Error:
            continue
        for row in rows:
            d = dict(zip(cols, row))
            user = str(d.get("username") or d.get("user") or "").strip()
            secret = str(d.get("password") or d.get("secret") or d.get("hash") or "").strip()
            ctype = str(d.get("credtype") or d.get("type") or "").lower()
            dom = str(d.get("domain") or "").strip()
            if not user or not secret or filters.is_placeholder(secret):
                continue
            n += 1
            if "hash" in ctype or (len(secret) == 32 and all(c in "0123456789abcdef" for c in secret.lower())):
                store.add(Evidence(kind="hash", user=user, domain=dom, hash=secret.lower(),
                                   hash_mode="1000", source=path, meta={"validated": True}))
                patterns.HASHES.append(("1000", "NTLM", secret.lower(), path, None))
                report.add("HIGH", "CRED PAIRS", path, None,
                           f"[netexec-validated] {dom}\\{user} NT={secret[:12]}…",
                           f"PtH: netexec smb <host> -u '{user}' -H {secret}")
            else:
                store.add(Evidence(kind="plaintext", user=user, domain=dom,
                                   plaintext=secret, cred=secret, source=path,
                                   meta={"validated": True}))
                # iter-140: escape ' in secret so a paste survives bash lexing.
                _secret_sh = secret.replace("'", "'\\''")
                report.add("CRITICAL", "CRED PAIRS", path, None,
                           f"[netexec-validated] {dom}\\{user}:{secret}",
                           f"reuse: netexec smb <host> -u '{user}' -p '{_secret_sh}' --continue-on-success")
    # admin relations -> pwned hosts
    for t in tables:
        if "admin" not in t.lower():
            continue
        try:
            cur.execute(f'SELECT * FROM "{t}"')
            if cur.fetchone():
                report.add("HIGH", "RECON", path, None,
                           f"netexec recorded admin access (table {t}) - check (Pwn3d!) hosts")
        except sqlite3.Error:
            pass
    con.close()
    if n:
        report.add("INFO", "RECON", path, None, f"netexec DB parsed: {n} stored creds")
    return n
