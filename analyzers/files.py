"""files.py - interesting files BY NAME (Linux + Windows) with next-step hints."""
import os, re
INTERESTING = [
    (re.compile(r'(?i)^id_(rsa|dsa|ecdsa|ed25519)$'), "SSH private key → chmod 600; ssh -i <f> user@ip", "HIGH"),
    (re.compile(r'(?i)^authorized_keys$'), "SSH authorized_keys → who can log in", "MEDIUM"),
    (re.compile(r'(?i)\.ppk$'), "PuTTY key → puttygen <f> -O private-openssh -o key", "HIGH"),
    (re.compile(r'(?i)\.(pem|key|pfx|p12)$'), "key/cert → openssl rsa -in <f> -noout", "HIGH"),
    (re.compile(r'(?i)\.(kdbx|kdb)$'), "KeePass DB → keepass2john | hashcat -m 13400", "HIGH"),
    (re.compile(r'(?i)\.(keytab)$'), "Kerberos keytab → klist -k <f>", "HIGH"),
    (re.compile(r'(?i)^shadow$'), "Linux /etc/shadow → unshadow + hashcat -m 1800", "HIGH"),
    (re.compile(r'(?i)^sudoers$'), "sudoers → check NOPASSWD / GTFOBins", "HIGH"),
    (re.compile(r'(?i)^\.bash_history$|_history$'), "shell history → typed passwords", "MEDIUM"),
    (re.compile(r'(?i)^\.(netrc|pgpass)$'), "Linux cred file → plaintext host:user:pass", "HIGH"),
    (re.compile(r'(?i)^\.git-credentials$'), "git creds → proto://user:pass@host", "HIGH"),
    (re.compile(r'(?i)^wp-config\.php$'), "WordPress config → DB creds + keys", "HIGH"),
    (re.compile(r'(?i)^(config|configuration|settings|database)\.(php|inc|yml|yaml)$'), "app config → DB/service creds", "HIGH"),
    (re.compile(r'(?i)^\.env$|^\.env\.'), "dotenv → APP_KEY/DB/API keys", "HIGH"),
    (re.compile(r'(?i)^tomcat-users\.xml$'), "Tomcat users → manager creds (WAR deploy)", "HIGH"),
    (re.compile(r'(?i)\.ovpn$'), "OpenVPN → embedded keys/creds", "MEDIUM"),
    (re.compile(r'(?i)^credentials$'), "cloud creds → aws sts get-caller-identity", "HIGH"),
    (re.compile(r'(?i)^(crontab)$|^cron\.'), "cron → writable root jobs = privesc", "MEDIUM"),
    (re.compile(r'(?i)^web\.config$|^app\.config$|^applicationhost\.config$'), "Windows config → connectionStrings", "HIGH"),
    (re.compile(r'(?i)unattend.*\.(xml|txt)$|sysprep.*\.xml$|autounattend'), "unattend → base64 local-admin pw", "HIGH"),
    (re.compile(r'(?i)^groups\.xml$|^scheduledtasks\.xml$|^services\.xml$|^datasources\.xml$|^printers\.xml$|^drives\.xml$'), "GPP file → cpassword; gpp-decrypt", "HIGH"),
    (re.compile(r'(?i)^(sam|system|security)$|^ntds\.dit$'), "Windows hive → impacket-secretsdump", "HIGH"),
    (re.compile(r'(?i)consolehost_history\.txt$'), "PowerShell history → typed creds", "HIGH"),
    (re.compile(r'(?i)\.(rdp|rdg)$|^rdcman\.settings$'), "RDP/RDCMan → saved passwords", "MEDIUM"),
    (re.compile(r'(?i)^winscp\.ini$'), "WinSCP → weakly encrypted sessions", "HIGH"),
    (re.compile(r'(?i)^(recentservers|sitemanager)\.xml$'), "FileZilla → base64 stored passwords", "HIGH"),
    (re.compile(r'(?i)\.(mdb|accdb)$'), "Access DB → mdb-tools", "MEDIUM"),
    (re.compile(r'(?i)\.(reg)$'), "registry export → grep AutoAdminLogon/password", "MEDIUM"),
    (re.compile(r'(?i)\.(ini|conf|cnf|cfg|properties|toml)$'), "config file → read for creds", "INFO"),
    (re.compile(r'(?i)\.(yml|yaml|json|xml)$'), "structured config → read for creds", "INFO"),
    (re.compile(r'(?i)\.(bak|old|orig|save|swp|~)$'), "backup → creds the live file lost", "MEDIUM"),
    (re.compile(r'(?i)\.(sql|dump)$'), "DB dump → grep INSERT INTO users", "MEDIUM"),
]
EXCLUDE_DIR = re.compile(r'/(site-packages|node_modules|vendor|dist-info|__pycache__|templates|languages|locale)/')
def analyze_tree(root, report):
    for dirpath, dirnames, filenames in os.walk(root):
        if EXCLUDE_DIR.search(dirpath + "/"): continue
        if ".git" in dirnames:
            report.add("MEDIUM", "INTERESTING FILES", os.path.join(dirpath, ".git"), None, "git repo → git log -p | grep -i pass")
        for name in filenames:
            full = os.path.join(dirpath, name)
            for rx, label, sev in INTERESTING:
                if rx.search(name):
                    report.add(sev, "INTERESTING FILES", full, None, label); break
