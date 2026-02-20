# IronheartEcho

**Category:** Reversing
**Difficulty:** Very Easy
**Points:** 725

## Description
> Beneath the Kanayama mountain shrine lies a half-buried dwarven smithy...

## Analysis

The challenge provides a binary named `iron`.
Opening it in a disassembler or using `strings` reveals some interesting data, but the flag is not in plain text.

Static analysis showed a function that processes data starting at offset `0x2150` in the binary.
The processing loop performs a simple XOR operation with the character `0x30` ('0').

## Solution

I extracted the bytes from the binary and wrote a Python script to decrypt them.

```python
def solve():
    with open("iron", "rb") as f:
        data = f.read()

    # Offset found via static analysis
    start_offset = 0x2150
    # Length of the flag string (approximate, or until null terminator)
    length = 50 
    
    encrypted_bytes = data[start_offset : start_offset + length]
    
    decrypted = []
    for b in encrypted_bytes:
        decrypted.append(b ^ 0x30)
        
    print("".join(chr(b) for b in decrypted))

if __name__ == "__main__":
    solve()
```

### Execution
Running the script revealed the flag.

**Flag:** `HTB{r3wr1tt3n_r3s0nanc3}`
