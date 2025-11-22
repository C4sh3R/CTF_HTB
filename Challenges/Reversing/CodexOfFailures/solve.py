#!/usr/bin/env python3
from pwn import *
import os

# Calculated errno values for each function index
# Based on analysis of the binary and test execution
errno_map = {
    0: 2,   # func_34aa: open non-existent file -> ENOENT (2)
    1: 10,  # func_3ccc: waitpid(-1) with no children -> ECHILD (10)
    2: 6,   # func_3886: open socket -> ENXIO (6)
    3: 1,   # func_3493: setuid(0) -> EPERM (1)
    4: 2,   # func_34aa
    5: 3,   # func_34d0: kill(deadbeef) -> ESRCH (3)
    6: 4,   # func_34ec: pause() interrupted by SIGALRM -> EINTR (4)
    7: 7,   # func_3a9d: execve with huge args -> E2BIG (7)
    8: 6,   # func_3886
    9: 5,   # func_36e8: read /proc/self/mem invalid -> EIO (5)
    10: 8,  # func_3bea: execve empty file -> ENOEXEC (8)
    11: 9,  # func_3c82: read(-1) -> EBADF (9)
    12: 2,  # func_34aa
    13: 4,  # func_34ec
    14: 7,  # func_3a9d
    15: 6,  # func_3886
    16: 10, # func_3ccc
    17: 9,  # func_3c82
    18: 8,  # func_3bea
    19: 5,  # func_36e8
    20: 6,  # func_3886
    21: 7,  # func_3a9d
    22: 4,  # func_34ec
    23: 3,  # func_34d0
    24: 2,  # func_34aa
    25: 1,  # func_3493
    26: 4,  # func_34ec
    27: 3   # func_34d0
}

key = ""
for i in range(28):
    err = errno_map[i]
    # The binary checks: input_char - 0x2f == errno
    # So: input_char = errno + 0x2f
    key += chr(err + 0x2f)

print(f"Calculated Key: {key}")

# Run the binary
p = process('./rev_codex_of_failures/chall')
p.sendlineafter(b"Enter key: ", key.encode())
p.interactive()
