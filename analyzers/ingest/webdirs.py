"""webdirs.py - parse web content-discovery output (gobuster/ffuf/feroxbuster/
dirb/dirsearch/nikto). Flags credential-relevant findings: login surfaces,
exposed .git/.env/backups, admin panels, basic-auth realms.
"""
import os
import re
import json
from analyzers.ingest.evidence import Evidence

_GOBUSTER = re.compile(r'^(/\S+)\s+\(Status:\s*(\d{3})\)')
_DIRB = re.compile(r'\+?\s*(https?://\S+)\s+\(CODE:(\d{3})')
_HOT = re.compile(r'(?i)(/\.git|/\.env|/\.svn|/admin|/login|/wp-admin|/phpmyadmin|'
                  r'/manager|/backup|/config|\.bak$|\.sql$|\.old$|\.zip$|/server-status|/actuator)')


def detect(path, head):
    h = head[:1000]
    if "(Status:" in h and "/" in h:
        return True            # gobuster
    if "(CODE:" in h and "SIZE:" in h:
        return True            # dirb
    if "- Nikto v" in h or "<niktoscan" in h:
        return True            # nikto
    if '"type":"response"' in h or '"type": "response"' in h:
        return True            # feroxbuster jsonl
    if '"results":' in h and '"input":' in h:
        return True            # ffuf json
    return False


def _flag(store, report, url, status, src):
    hot = _HOT.search(url)
    sev = "CRITICAL" if re.search(r'(?i)/\.git|/\.env|\.bak$|\.sql$', url) else \
          "HIGH" if hot else "INFO"
    fact = "exposed_secret" if sev == "CRITICAL" else ("login_surface" if hot else "")
    if hot or sev != "INFO":
        store.add(Evidence(kind="web", service="http", fact=fact, source=src,
                           meta={"url": url, "status": status}))
        hint = "git-dump? manual review" if "/.git" in url else \
               "read it for secrets" if re.search(r'(?i)\.env|\.bak|\.sql|config', url) else \
               "try default creds / login" if re.search(r'(?i)login|admin|manager', url) else ""
        report.add(sev, "RECON", src, None, f"web {status} {url}", hint)


def parse(path, store, report):
    n = 0
    try:
        with open(path, "r", errors="ignore") as fh:
            raw = fh.read()
    except OSError:
        return 0
    # ffuf json
    if raw.lstrip().startswith("{") and '"results"' in raw[:2000]:
        try:
            for r in json.loads(raw).get("results", []):
                url = r.get("url") or r.get("input", {}).get("FUZZ", "")
                _flag(store, report, url, r.get("status", ""), path)
                n += 1
            return n
        except ValueError:
            pass
    for line in raw.splitlines():
        line = line.strip()
        # feroxbuster jsonl
        if line.startswith("{") and '"response"' in line:
            try:
                o = json.loads(line)
                if o.get("type") == "response":
                    _flag(store, report, o.get("url", ""), o.get("status", ""), path)
                    n += 1
            except ValueError:
                pass
            continue
        m = _GOBUSTER.match(line) or _DIRB.search(line)
        if m:
            _flag(store, report, m.group(1), m.group(2), path)
            n += 1
    return n
