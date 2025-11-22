# ForgottenVault

**Category:** Reversing
**Difficulty:** Easy
**Points:** 875

## Description
> An ancient machine sealed deep within a vault beneath Kageno begins to hum, waiting for a master...

## Analysis

The challenge provides a 64-bit ELF binary `forgotten_vault`.

### Main Function
The `main` function performs the following actions:
1. Calls `setup()`.
2. Prints some banner text.
3. Reads an integer input using `scanf`.
4. Calls `check_pin(input)`.
5. If `check_pin` returns, it enters a loop that prints "Incorrect code" characters slowly.

### Setup Function
The `setup` function installs a signal handler for signal 8 (`SIGFPE` - Floating Point Exception).
```c
// ...
mov     edi, 8
lea     rsi, [rbp-0xa0]
xor     eax, eax
call    sigaction
// ...
```

### Handler Function
The `handler` function (at `0x1290`) contains logic to decrypt a string using XOR and bitwise operations and print it. This strongly suggests that triggering the signal handler is the win condition.

### Check_pin Function
The `check_pin` function performs a calculation and then a division.
```c
// ...
mov     ecx, DWORD PTR [rbp-0x4]    // ecx = pin
sub     ecx, 0x4149                 // ecx = pin - 0x4149
movsxd  rcx, ecx                    // Sign extend to 64-bit
movsxd  rdx, DWORD PTR [rbp-0x4]    // rdx = pin (sign extended)
movabs  rsi, 0xac979988
add     rdx, rsi                    // rdx = pin + 0xac979988
add     rcx, rdx                    // rcx = (pin - 0x4149) + (pin + 0xac979988)
add     rcx, 1                      // rcx = rcx + 1
cqo
idiv    rcx                         // Divide by rcx
// ...
```

The `idiv rcx` instruction will trigger a `SIGFPE` if `rcx` is 0.

## Solution

We need to find a `pin` such that:
`(pin - 0x4149) + (pin + 0xac979988) + 1 == 0`

Let's solve for `pin`. Note that the operations are on 32-bit integers sign-extended to 64-bit.

I wrote a small C script to verify the behavior and find the correct PIN.

```c
#include <stdio.h>
#include <stdint.h>

int main() {
    // We need rcx to be 0.
    // rcx = (pin - 0x4149) + (pin + 0xac979988) + 1
    // 2 * pin + (-0x4149 + 0xac979988 + 1) = 0
    // 2 * pin = - (0xac979988 - 0x4149 + 1)
    // 2 * pin = - (2895616392 - 16713 + 1)
    // 2 * pin = - 2895599680
    // pin = -1447799840
    
    int32_t pin = -1447799840;
    
    int32_t ecx = pin - 0x4149;
    int64_t rcx = (int64_t)ecx;
    int64_t rdx = (int64_t)pin;
    int64_t rsi = 0xac979988;
    
    rdx = rdx + rsi;
    rcx = rcx + rdx;
    rcx = rcx + 1;
    
    printf("PIN: %d\n", pin);
    printf("Resulting divisor (rcx): %ld\n", rcx);
    
    return 0;
}
```

Running the verification confirmed that `pin = -1447799840` results in `rcx = 0`.

### Execution
Running the binary with this PIN:
```bash
$ echo "-1447799840" | ./forgotten_vault
Deep beneath Kageno, a forgotten vault stirs.
A rusted mechanism hums faintly, waiting for a code long lost.

Enter code> Etched letters start to appear... Access Granted, HTB{s1gN4l_H4ndL3r$-t0_w1n?}
```

**Flag:** `HTB{s1gN4l_H4ndL3r$-t0_w1n?}`
