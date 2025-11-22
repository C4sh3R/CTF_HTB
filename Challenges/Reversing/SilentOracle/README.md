# SilentOracle

**Category:** Reversing
**Difficulty:** Medium
**Points:** 950

## Description
> Beneath the temple sits a mute sage: the Silent Oracle. It answers only in sighs and the faint click of the world around it...

## Analysis

The challenge provides a stripped 64-bit ELF binary `chall`.
The binary connects to a remote service (or is the service running remotely).

### Main Function
The `main` function (located at `0x1283` in my analysis) reads input using `fgets` and calls a check function at `0x11fc`.

### Check Function
The check function compares the input string against a stored string (which in the local binary is `HTB{test_flag_hahaha}`).

The comparison loop logic is:
1. Compare `input[i]` with `flag[i]`.
2. If they match, increment `i` and continue.
3. If they mismatch:
    - Print "UH OH! ..." (and some ANSI colors).
    - Sleep for 5 seconds.
    - Return 0 (failure).
4. If the loop finishes (because `input` ended before mismatch):
    - Return 0 (failure) immediately, **without sleeping**.

### The Oracle
This behavior creates an oracle that allows us to brute-force the flag character by character.
- If we send a string that has a wrong character at the end (e.g., `HTB{X`), the server will print "UH OH" and sleep for 5 seconds.
- If we send a string that is a correct prefix of the flag (e.g., `HTB{`), the server will process it, reach the end of our input, and exit immediately (printing "Access Denied" but **not** "UH OH").

So, we can distinguish between a correct character and an incorrect one by checking for the presence of "UH OH" (or by measuring the time, but checking the output is more reliable).

## Solution

I wrote a Python script using `pwntools` to brute-force the flag.
To speed up the process (since every wrong guess costs 5 seconds), I used `concurrent.futures` to try multiple characters in parallel.

```python
from pwn import *
import string
import time
import concurrent.futures

HOST = '154.57.164.81'
PORT = 31367

charset = string.ascii_letters + string.digits + "_{}?!@#%&"

def check_char(current_flag, char):
    candidate = current_flag + char
    try:
        r = remote(HOST, PORT, level='error')
        r.sendline(candidate.encode())
        
        # Read all output. 
        # If "UH OH" is present, it means we triggered the mismatch path (Wrong char).
        # If "UH OH" is NOT present (and connection closed), it means we hit the short-input path (Right char).
        data = r.recvall(timeout=6)
        r.close()
        
        if b"UH OH" in data:
            return False, char
        else:
            return True, char
            
    except Exception as e:
        return False, char

flag = "HTB{"
print(f"Starting parallel brute force. Current flag: {flag}")

while not flag.endswith("}"):
    found_char = None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_char, flag, char): char for char in charset}
        
        for future in concurrent.futures.as_completed(futures):
            is_correct, char = future.result()
            if is_correct:
                found_char = char
                print(f"Found char: {char}")
                executor.shutdown(wait=False, cancel_futures=True)
                break
    
    if found_char:
        flag += found_char
        print(f"Current flag: {flag}")
    else:
        print("Could not find next character. Exiting.")
        break

print(f"Final Flag: {flag}")
```

### Execution
Running the script revealed the flag character by character.

**Flag:** `HTB{Tim1ng_z@_h0ll0w_t3ll5}`
