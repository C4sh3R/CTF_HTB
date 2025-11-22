# The Paper General's Army

## Information

- **Difficulty**: Very Easy
- **Category**: Misc
- **Platform**: HackTheBox
- **Date**: November 21, 2025
- **Points**: 775

## Challenge Description

"When the moon was high and the world was quiet, the Paper General would whisper a single word: “Fold.” Under that silver glow, each soldier of parchment would split like a reflection in still water, doubling the ranks without a sound. Only a trace of that forgotten ritual remains — the secret mathematics behind a growing legion. Tonight, beneath the same moon, you are given the chance to summon the Folded Army yourself."

The challenge asks us to calculate the final number of soldiers given an initial number $N$ and a number of folds $K$. Each fold doubles the number of soldiers.

**Input Format:**
- First line: Integer $T$ (number of test cases).
- Next $T$ lines: Two integers $N$ and $K$.

**Constraints:**
- $1 \le T \le 500000$
- $1 \le N \le 100$
- $1 \le K \le 50$

## Reconnaissance

### Analysis

The problem is a straightforward mathematical calculation.
If we start with $N$ soldiers:
- After 1 fold: $N \times 2$
- After 2 folds: $N \times 2 \times 2 = N \times 2^2$
- ...
- After $K$ folds: $N \times 2^K$

This can be efficiently calculated using the bitwise left shift operator: `N << K`.

Given the large number of test cases ($T = 500,000$), we need an efficient I/O handling method. Reading all input at once (`sys.stdin.read()`) is much faster than reading line by line in Python.

## Exploitation

### Solution

I implemented a Python script that reads the entire input, parses the integers, and computes the result for each test case.

```python
import sys

def solve():
    # Read all input from stdin at once
    input_data = sys.stdin.read().split()
    if not input_data:
        return

    iterator = iter(input_data)
    try:
        num_test_cases = int(next(iterator))
    except StopIteration:
        return

    results = []
    for _ in range(num_test_cases):
        try:
            n = int(next(iterator))
            k = int(next(iterator))
            # Calculate N * 2^K using bitwise shift
            ans = n << k
            results.append(str(ans))
        except StopIteration:
            break
    
    # Print all results joined by newlines
    print('\n'.join(results))

if __name__ == '__main__':
    solve()
```

### Flag

`HTB{th3_f0ld3d_l3g10n_r1s3s_1n_th3_m00nl1ght}`
