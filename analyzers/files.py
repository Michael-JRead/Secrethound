"""files.py - interesting files BY NAME (Linux + Windows + AD) with next-step
hints. Coverage is modelled on linPEAS sensitive_files.yaml. Noise files
(unzipped office docs, nmap XML, tool .bak output) are skipped via filters.
"""
import os
import re
from analyzers import filters

INTERESTING = [
    # ── SSH / keys ─────────────────────────────────────────────────────────
    (re.compile(r'(?i)^id_(rsa|dsa|ecdsa|ed25519)$'), "SSH private key → chmod 600; ssh -i <f> user@ip", "HIGH"),
    (re.compile(r'(?i)^authorized_keys$'), "SSH authorized_keys → who can log in (check from=/command=)", "MEDIUM"),
    (re.compile(r'(?i)^known_hosts$'), "SSH known_hosts → lateral-movement target list", "INFO"),
    (re.compile(r'(?i)\.ppk$'), "PuTTY key → puttygen <f> -O private-openssh -o key", "HIGH"),
    (re.compile(r'(?i)\.(pem|key|pfx|p12)$'), "key/cert → openssl rsa -in <f> -noout  (.pfx: certipy auth -pfx <f>)", "HIGH"),
    (re.compile(r'(?i)\.(jks|keystore)$|^cacerts$'), "Java keystore → keytool -list; keystore2john → hashcat 15500", "MEDIUM"),
    (re.compile(r'(?i)\.(gpg|asc|pgp)$|^secring\.gpg$|^pubring\.kbx$'), "GPG keyring → gpg --import; gpg2john secret.asc", "HIGH"),
    # ── password stores ────────────────────────────────────────────────────
    (re.compile(r'(?i)\.(kdbx|kdb)$'), "KeePass DB → keepass2john | hashcat -m 13400", "HIGH"),
    (re.compile(r'(?i)^keepass\.config.*\.xml$'), "KeePass config → keyfile/trigger path", "MEDIUM"),
    (re.compile(r'(?i)\.psafe3$'), "Password Safe DB → pwsafe2john | hashcat -m 5200", "HIGH"),
    # ── Active Directory / Kerberos (OSCP+ core) ───────────────────────────
    (re.compile(r'(?i)\.keytab$'), "Kerberos keytab → klist -k <f>; getTGT.py -keytab", "HIGH"),
    (re.compile(r'(?i)\.kirbi$'), "Kerberos ticket → ticketConverter.py <f> t.ccache; export KRB5CCNAME", "HIGH"),
    (re.compile(r'(?i)\.ccache$|^krb5cc_'), "Kerberos ccache → export KRB5CCNAME=<f>; nxc smb <dc> --use-kcache", "HIGH"),
    (re.compile(r'(?i)^secrets\.(ldb|tdb)$'), "Samba/SSSD secrets → tdbdump (machine acct creds)", "HIGH"),
    (re.compile(r'(?i)^krb5\.keytab$'), "service keytab → klist -k; extract keys", "HIGH"),
    (re.compile(r'(?i)bloodhound.*\.(json|zip)$'), "BloodHound data → import; review owned/paths", "INFO"),
    # ── Linux system creds ────────────────────────────────────────────────
    (re.compile(r'(?i)^shadow$|^shadow-$|^shadow~$|^gshadow$'), "Linux shadow → unshadow + hashcat -m 1800/500/3200", "HIGH"),
    (re.compile(r'(?i)^passwd$|^master\.passwd$'), "Linux passwd → check field 2 for inline hashes; writable = privesc", "MEDIUM"),
    (re.compile(r'(?i)^sudoers$'), "sudoers → check NOPASSWD / GTFOBins", "HIGH"),
    (re.compile(r'(?i)^opasswd$'), "PAM opasswd → old password hashes", "MEDIUM"),
    (re.compile(r'(?i)_history$|^\.(bash|zsh|sh|mysql|psql|rediscli|python|sqlite)_history$'), "shell/db history → typed passwords (grep -p, IDENTIFIED BY)", "MEDIUM"),
    (re.compile(r'(?i)^\.viminfo$|^\.lesshst$'), "editor history → recently edited secrets", "INFO"),
    (re.compile(r'(?i)^\.(netrc|pgpass)$'), "Linux cred file → plaintext host:user:pass", "HIGH"),
    (re.compile(r'(?i)^\.(npmrc|pypirc|s3cfg|boto|git-credentials)$'), "tool cred file → _authToken / user:pass / keys", "HIGH"),
    (re.compile(r'(?i)^\.(msmtprc|fetchmailrc|netrc)$'), "mail/transfer creds → plaintext user:pass", "HIGH"),
    (re.compile(r'(?i)^pg_hba\.conf$|^postgresql\.conf$|^\.mylogin\.cnf$|^debian\.cnf$|^my\.cnf$'), "DB auth config → bind creds / debian-sys-maint pw", "HIGH"),
    (re.compile(r'(?i)^ipsec\.secrets$|^psk\.txt$'), "IPSec PSK → plaintext pre-shared key", "HIGH"),
    (re.compile(r'(?i)^sssd\.conf$|^ldap\.conf$|^\.ldaprc$|^smb\.conf$|^smbpasswd$|^nsswitch\.conf$'), "LDAP/Samba config → bindpw / ldap_default_authtok", "HIGH"),
    (re.compile(r'(?i)^wpa_supplicant.*\.conf$|\.nmconnection$'), "WiFi config → psk= pre-shared key", "MEDIUM"),
    (re.compile(r'(?i)^\.google_authenticator$'), "TOTP seed → 2FA secret", "MEDIUM"),
    # ── cloud / devops ─────────────────────────────────────────────────────
    (re.compile(r'(?i)^credentials$'), "cloud creds → aws sts get-caller-identity", "HIGH"),
    (re.compile(r'(?i)^kubeconfig$|^admin\.conf$|^kubelet\.conf$'), "kubeconfig → kubectl --kubeconfig <f> get secrets", "HIGH"),
    (re.compile(r'(?i)\.tfstate(\.backup)?$|^terraform\.tfvars$'), "Terraform state/vars → plaintext secrets", "HIGH"),
    (re.compile(r'(?i)^credentials\.xml$|^hudson\.util\.secret$|^master\.key$'), "Jenkins creds → decrypt with master.key + hudson.util.Secret", "HIGH"),
    (re.compile(r'(?i)^vault.*\.ya?ml$|^group_vars$|^host_vars$'), "Ansible Vault → ansible-vault view; ansible2john → hashcat 16900", "HIGH"),
    (re.compile(r'(?i)^azureProfile\.json$|^accessTokens\.json$|^\.roadtools_auth$|^msal_token_cache\.json$'), "Azure tokens → roadrecon / az account", "HIGH"),
    (re.compile(r'(?i)^legacy_credentials.*|^adc\.json$|^application_default_credentials\.json$'), "GCP creds → gcloud auth", "HIGH"),
    (re.compile(r'(?i)^\.env$|^\.env\.|^\.envrc$|^\.flaskenv$'), "dotenv → APP_KEY/DB/API keys", "HIGH"),
    # ── browser saved creds ────────────────────────────────────────────────
    (re.compile(r'(?i)^logins\.json$|^key4\.db$|^cookies\.sqlite$'), "Firefox creds → firefox_decrypt.py", "HIGH"),
    # iter-11: macOS keychain artifacts
    (re.compile(r'(?i)^login\.keychain(?:-db)?$|^keychain-\d+\.db$|^System\.keychain$'),
     "macOS keychain → security dump-keychain -d <f> (interactive) | chainbreaker.py -f <f>", "HIGH"),
    (re.compile(r'(?i)^kcpassword$'),
     "macOS auto-login token → /etc/kcpassword XOR-decode (published key); reuse against login pw", "HIGH"),
    # iter-11: mRemoteNG / Remmina / SecureCRT saved connection profiles
    (re.compile(r'(?i)^confCons(?:\.\w+)?\.xml$'),
     "mRemoteNG confCons → mremoteng-decrypt.py (default AES key 'mR3m')", "HIGH"),
    (re.compile(r'(?i)\.remmina$'),
     "Remmina connection → ~/.config/remmina/RemminaSecret hash + AES-CBC", "HIGH"),
    (re.compile(r'(?i)^(?:portable_)?connections\.json$'),
     "DBeaver / HeidiSQL conn store → hex(...) XOR-reversible passwords", "HIGH"),
    (re.compile(r'(?i)^login data$|^cookies$'), "Chrome creds → DPAPI decrypt", "HIGH"),
    # iter-22 (corpus mine wwzwk72m3): Chrome/Edge 'Local State' JSON contains
    # the os_crypt.encrypted_key (b64 of DPAPI-wrapped AES key) needed to
    # decrypt Login Data/Cookies. Required step on every modern Chromium box.
    (re.compile(r'(?i)^local state$'),
     "Chrome/Edge Local State → b64-decode os_crypt.encrypted_key, strip 'DPAPI' prefix, "
     "impacket-dpapi masterkey to unwrap AES key for Login Data/Cookies decryption", "HIGH"),
    # iter-22: Chrome 127+ app_bound_encrypted_key (additional SYSTEM-DPAPI layer)
    (re.compile(r'(?i)^app[\s_-]?bound[\s_-]?encrypted[\s_-]?key.*$'),
     "Chrome 127+ app_bound_encrypted_key → needs SYSTEM DPAPI + IElevator COM", "HIGH"),
    # iter-22: Login Data / Cookies WAL+SHM sidecars (often hold un-merged rows)
    (re.compile(r'(?i)^(?:login\s*data|cookies)-(?:journal|wal|shm)$'),
     "Chrome WAL/SHM sidecar - merge BEFORE extraction: cp 'Login Data*' /tmp; sqlite3 .databases", "MEDIUM"),
    # iter-22: Firefox legacy (pre-58) credential stores
    (re.compile(r'(?i)^(?:signons|signedInUser)\.sqlite$|^key3\.db$'),
     "Firefox legacy creds (pre-58) → key3.db (Berkeley DB) + signons.sqlite; firepwd.py", "HIGH"),
    # iter-22: HackBrowserData per-browser output filenames
    (re.compile(r'(?i)^(?:chrome|edge|brave|firefox|opera|vivaldi)_(?:password|cookie|history|bookmark|downloads?)\.(?:csv|json)$'),
     "HackBrowserData export → cat <file>; passwords are PLAINTEXT in this output", "CRITICAL"),
    # iter-22: DonPAPI decrypted loot directory layout
    (re.compile(r'(?i)/donpapi/.*/(?:chrome|firefox|vaults|credentials)/decrypted/'),
     "DonPAPI decrypted creds → cat *.txt; plaintext DPAPI-recovered creds", "CRITICAL"),
    # iter-22: hashcat $mozilla$ hash file marker
    (re.compile(r'(?i)^.*mozilla.*\.(hash|txt|hashes)$|^firefox_hash\.txt$'),
     "Firefox $mozilla$ hash file → hashcat -m 26000 (3DES) or -m 26100 (AES); recovers primary pw", "HIGH"),
    # ── web app configs ────────────────────────────────────────────────────
    # iter-17 (corpus mine wkl2kkzn5): known PHP webshell artifacts (HTB Bashed)
    (re.compile(r'(?i)^(phpbash|c99|c100|r57|wso|b374k|simple[_-]?backdoor|'
                r'0byt3m1n1|p0wny|alfa(?:sh3ll|v\d+)?|mini[_-]?shell|webshell|'
                r'indoxploit|fenix)\.php$|^cmd\.php$|^shell\.php$|^backdoor\.php$'),
     "PHP webshell artifact → curl <url> -d 'cmd=id' or visit + run cmds", "CRITICAL"),
    (re.compile(r'(?i)^wp-config\.php$'), "WordPress config → DB creds + keys", "HIGH"),
    (re.compile(r'(?i)^\.htpasswd$'), "Apache basic-auth → hashcat -m 1600 (apr1)", "HIGH"),
    (re.compile(r'(?i)^(config|configuration|settings|database|db|storage)\.(php|inc|yml|yaml)$'), "app config → DB/service creds", "HIGH"),
    (re.compile(r'(?i)^tomcat-users\.xml$'), "Tomcat users → manager creds (WAR deploy)", "HIGH"),
    (re.compile(r'(?i)\.ovpn$'), "OpenVPN → auth-user-pass / embedded keys", "MEDIUM"),
    (re.compile(r'(?i)^(crontab)$|^cron\.|^crontab\.db$'), "cron → writable root jobs / passwords on cmdline", "MEDIUM"),
    # ── Windows ────────────────────────────────────────────────────────────
    (re.compile(r'(?i)^web\.config$|^app\.config$|^applicationhost\.config$|^machine\.config$'), "Windows config → connectionStrings / machineKey", "HIGH"),
    (re.compile(r'(?i)unattend.*\.(xml|txt)$|sysprep.*\.xml$|autounattend'), "unattend → base64 local-admin pw", "HIGH"),
    (re.compile(r'(?i)^cloudbase-init.*\.conf$'), "cloudbase-init → Windows admin pw", "HIGH"),
    (re.compile(r'(?i)^groups\.xml$|^scheduledtasks\.xml$|^services\.xml$|^datasources\.xml$|^printers\.xml$|^drives\.xml$'), "GPP file → cpassword; gpp-decrypt", "HIGH"),
    (re.compile(r'(?i)^sitelist\.xml$'), "McAfee SiteList → encrypted domain creds (fixed 3DES key)", "HIGH"),
    (re.compile(r'(?i)^(sam|system|security)$|^ntds\.dit$'), "Windows hive → impacket-secretsdump", "HIGH"),
    (re.compile(r'(?i)consolehost_history\.txt$'), "PowerShell history → typed creds", "HIGH"),
    (re.compile(r'(?i)\.(rdp|rdg)$|^rdcman\.settings$'), "RDP/RDCMan → saved passwords (DPAPI)", "MEDIUM"),
    (re.compile(r'(?i)^winscp\.ini$'), "WinSCP → weakly encrypted sessions", "HIGH"),
    (re.compile(r'(?i)^(recentservers|sitemanager)\.xml$'), "FileZilla → base64 stored passwords", "HIGH"),
    (re.compile(r'(?i)^ultravnc\.ini$|^vnc.*\.(ini|txt|reg)$'), "VNC → reversible DES password (vncpwd)", "HIGH"),
    (re.compile(r'(?i)\.(mdb|accdb)$'), "Access DB → mdb-tools", "MEDIUM"),
    (re.compile(r'(?i)\.(reg)$'), "registry export → grep AutoAdminLogon/DefaultPassword", "MEDIUM"),
    # ── iter-8 round-1 file-loot adds ──────────────────────────────────────
    # DPAPI per-user / per-machine master-key files (the GUID-shaped names):
    (re.compile(r'(?i)\\Protect\\S-1-5-21-[\d-]+\\[a-f0-9-]{36}$|/Protect/S-1-5-21-[\d-]+/[a-f0-9-]{36}$'),
     "DPAPI masterkey → impacket-dpapi masterkey -file <f> -sid <SID> -password <pw>", "HIGH"),
    # WindowsHello PIN / NGC containers:
    (re.compile(r'(?i)\.ngc$|\\Ngc\\|/Ngc/'),
     "WindowsHello NGC container → DPAPI PIN-protected creds", "MEDIUM"),
    # Veeam VBR backup metadata + creds:
    (re.compile(r'(?i)\.(vbm|vlb|vab|vbk)$'),
     "Veeam backup metadata → stored repo + guest creds (DPAPI inside)", "HIGH"),
    # SCCM PolicyAgent / NAA blob (datatransferservice cached policy):
    (re.compile(r'(?i)CcmStore\.sdf$|DataTransferService.*\.log$|^Policy\.\d+\.\d+$'),
     "SCCM policy / NAA blob → sccmhunter / SharpSCCM offline extraction", "HIGH"),
    # Microsoft DPAPI Credential files:
    (re.compile(r'(?i)\\Credentials\\[a-f0-9]{32,}$|/Credentials/[a-f0-9]{32,}$'),
     "Windows Credential vault file (DPAPI) → mimikatz dpapi::cred", "HIGH"),
    # NetSh wlan profile XML:
    (re.compile(r'(?i)wlan.*-profile.*\.xml$|^Interface_.*\.xml$'),
     "wlan profile → WiFi PSK (cleartext or DPAPI per machine)", "MEDIUM"),
    # Vault binary / Bitwarden / 1Password DBs:
    (re.compile(r'(?i)\.(opvault|1pif|bitwarden\.json|vault)$'),
     "password manager export/DB → review for plaintext entries", "HIGH"),
    # PostgreSQL pg_hba.conf:
    (re.compile(r'(?i)^pg_hba\.conf$'),
     "pg_hba.conf → 'trust' auth lines = unauth DB access", "HIGH"),
    # Asterisk manager / VoIP:
    (re.compile(r'(?i)^manager\.conf$'),
     "asterisk manager.conf → AMI secret=", "HIGH"),
    # ZNC IRC bouncer:
    (re.compile(r'(?i)^znc\.conf$'),
     "znc.conf → user Pass = + SASL credentials", "MEDIUM"),
    # WireGuard:
    (re.compile(r'(?i)\.(wg|wg-quick)$|^wg0\.conf$'),
     "WireGuard config → PrivateKey + peer connectivity", "HIGH"),
    # Sliver / Mythic / NimPlant / Brute Ratel implant state on operator disk:
    (re.compile(r'(?i)^implant\.config$|^operator\.cfg$|sliver-\d+\.[\w.-]+$|^\.mythic.*\.json$'),
     "C2 implant config → operator-side leaked C2 URL + auth", "HIGH"),
    # GitHub Personal Access Token files:
    (re.compile(r'(?i)^\.netrc$|^github_token$|^\.git-credentials$|\.npmrc$'),
     "tool cred file → _authToken / token / user:pass", "HIGH"),
    # Hashcat potfile / John pot:
    (re.compile(r'(?i)^hashcat\.potfile$|\.potfile$|\.pot$|^john\.pot$'),
     "cracking potfile → already-cracked hash:plain pairs (we parse the content)", "HIGH"),
    # Maven / Gradle / Pipenv credentials caches:
    (re.compile(r'(?i)^settings\.xml$|^gradle\.properties$|^\.npmrc$|^\.gem/credentials$|^\.pypirc$'),
     "build-tool cred cache → repo auth tokens", "MEDIUM"),
    # ── iter-25 Tier-3 from corpus mine wwzwk72m3 ─────────────────────────
    # MSSQL Reporting Services rsreportserver.config: holds DSN with
    # symmetric-encrypted creds (DPAPI on machine key). Operator can
    # decrypt offline once they have the SQL server's machine key.
    (re.compile(r'(?i)^rsreportserver\.config$|^rssvrpolicy\.config$|'
                r'^rsreportdesigner\.config$'),
     "SSRS Reporting Services config → encrypted DSN; "
     "needs machine key from same host", "HIGH"),
    # VHD / VHDX virtual disk - mount + grep for SAM/SYSTEM/passwords.
    # Operator-collected backup loot, very common in pre-built lab images.
    (re.compile(r'(?i)\.(vhd|vhdx|vmdk|vdi|qcow2?)$'),
     "virtual disk image → 7z l <f>; mount loop + grep SAM/Users/notes", "HIGH"),
    # TightVNC / RealVNC registry export (.reg) with encrypted Password
    # value (DES with the public TightVNC key - vncpwd / vncdec).
    (re.compile(r'(?i)^tightvnc.*\.reg$|^realvnc.*\.reg$|^vnc-?server.*\.reg$'),
     "VNC server registry export → vncpwd on the Password value", "HIGH"),
    # MSSQL backup .bak file - holds NTLM hashes if the box's SQL was
    # AD-integrated, or app DB credentials at minimum.
    (re.compile(r'(?i)\.bak$'),
     "backup file (potentially MSSQL .bak) → mdf-tool / RESTORE FILELISTONLY", "INFO"),
    # PCAP - protocol captures with cleartext Basic / FTP / Telnet creds.
    # We can't parse pcap fully without libpcap, but strings-grep often
    # surfaces the obvious wins; operator can also run with pcredz / NetworkMiner.
    (re.compile(r'(?i)\.(pcap|pcapng|cap)$'),
     "packet capture → strings <f> | grep -iE 'authorization|user|pass|"
     "magic|user:'; pcredz / NetworkMiner", "MEDIUM"),
    # OpenSSH ssh-agent socket forwarded into a directory or .ssh/agent.*
    (re.compile(r'(?i)\.ssh/(?:agent\.|known_hosts)|^authorized_keys$|^known_hosts$'),
     "SSH agent / known_hosts → host inventory + key trust path", "INFO"),
    # Apache mod_jk worker properties (Tomcat AJP creds)
    (re.compile(r'(?i)^workers\.properties$|^mod_jk\.conf$'),
     "Apache mod_jk → Tomcat AJP backend creds / target inventory", "MEDIUM"),
    # Vagrant / Packer build artifact (frequently contains image build creds)
    (re.compile(r'(?i)^Vagrantfile$|^packer.*\.json$'),
     "Vagrant/Packer build script → embedded ssh_password / winrm_password", "MEDIUM"),

    # ── generic / catch-all (lowest priority) ──────────────────────────────
    (re.compile(r'(?i)\.(ini|conf|cnf|cfg|properties|toml)$'), "config file → read for creds", "INFO"),
    (re.compile(r'(?i)\.(yml|yaml|json|xml)$'), "structured config → read for creds", "INFO"),
    (re.compile(r'(?i)\.(bak|old|orig|save|swp|~)$'), "backup → creds the live file lost", "MEDIUM"),
    (re.compile(r'(?i)\.(sql|dump)$'), "DB dump → grep INSERT INTO users / IDENTIFIED BY", "MEDIUM"),
]

# tool-generated backups/output that look interesting but never are
_TOOL_NOISE = re.compile(r'(?i)(dacledit|certipy|bloodhound|ldapdomaindump)[-_]?.*\.(bak|json|zip)$'
                         r'|.*-\d{8}-\d{6}\.bak$')


def analyze_tree(root, report, skip_paths=None):
    skip_paths = skip_paths or set()
    for dirpath, dirnames, filenames in os.walk(root):
        # iter-15: sort dirnames and filenames so file walk is deterministic
        # across OS / filesystem. Same fix as secrethound.py iter_files().
        dirnames[:] = sorted(d for d in dirnames
                             if not filters.should_skip_dir(d, os.path.join(dirpath, d)))
        # flag git repos (but don't descend - .git is pruned above)
        if os.path.isdir(os.path.join(dirpath, ".git")):
            report.add("INFO", "INTERESTING FILES", os.path.join(dirpath, ".git"), None,
                       "git repo → git log -p | grep -iE 'pass|secret|key'")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if full in skip_paths or filters.is_noise_file(full, name) or _TOOL_NOISE.search(name):
                continue
            if name.lower().endswith(".json") and filters.is_secrethound_output(full):
                continue
            # iter-24: also match against the FULL path so patterns that
            # require directory context (e.g. /Credentials/<hex>, AppData
            # paths, /Cookies/... browser-store layouts) actually fire.
            # Previously these were dead code - matched .name only.
            for rx, label, sev in INTERESTING:
                if rx.search(name) or rx.search(full):
                    report.add(sev, "INTERESTING FILES", full, None, label)
                    break
