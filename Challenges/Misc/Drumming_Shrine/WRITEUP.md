# Drumming Shrine

## Information

- **Difficulty**: Easy
- **Category**: Misc
- **Platform**: HackTheBox
- **Date**: November 21, 2025
- **Points**: 825

## Challenge Description

"At dusk, Mount Tsukimori breathes. The old shrine’s drums answer with a pulse that never quite fades—steady, familiar, unsettling. Is it the wind finding the same grooves in cracked wood, or a spirit caught in a loop, replaying a perfect rhythm it refuses to forget? Listen closely. If the mountain is repeating itself, you’ll hear the seam."

The challenge asks us to determine if a given sequence of beats (integers) can be formed by repeating a smaller prefix one or more times.

**Input Format:**
- First line: Integer $N$ (length of the rhythm).
- Second line: $N$ space-separated integers $a_1, a_2, \dots, a_n$.

**Output Format:**
- Print `YES` if the entire rhythm can be obtained by repeating a smaller prefix.
- Otherwise, print `NO`.

**Constraints:**
- $1 \le N \le 200,000$
- $1 \le a_i \le 10^9$

## Reconnaissance

### Analysis

The problem asks whether the sequence $S$ of length $N$ is periodic with a period length $L < N$.
If $S$ is periodic with period $L$, then $S[i] = S[i+L]$ for all valid $i$, and $N$ must be divisible by $L$.
This implies that the prefix of length $L$ is repeated $N/L$ times to form $S$.

This problem can be efficiently solved using the Knuth-Morris-Pratt (KMP) algorithm's failure function (often denoted as $\pi$).
The value $\pi[i]$ stores the length of the longest proper prefix of the substring $S[0 \dots i]$ that is also a suffix of this substring.

For the entire string $S$ of length $N$, let $len = \pi[N-1]$.
This $len$ represents the length of the longest proper prefix of $S$ that is also a suffix of $S$.
If $S$ has a period $L$, then $S$ has a prefix of length $N-L$ which is also a suffix.
The shortest period $L_{min}$ corresponds to the longest such prefix-suffix length $len_{max}$.
Thus, $L_{min} = N - \pi[N-1]$.

However, this is only a valid period if the prefix-suffix actually covers the repetitions correctly.
The condition for $S$ to be periodic with period $L = N - \pi[N-1]$ is:
1. $\pi[N-1] > 0$ (so that $L < N$)
2. $N \% L == 0$ (so that the period divides the length perfectly)

If these conditions are met, the answer is `YES`. Otherwise, `NO`.

Time Complexity: $O(N)$ to compute the $\pi$ array.
Space Complexity: $O(N)$ to store the $\pi$ array.

## Exploitation

### Solution

I implemented the solution in Python using the KMP failure function logic.

```python
import sys

# Increase recursion depth just in case
sys.setrecursionlimit(200005)

def solve():
    # Read all input
    input_data = sys.stdin.read().split()
    if not input_data:
        return

    iterator = iter(input_data)
    try:
        n = int(next(iterator))
    except StopIteration:
        return

    # Read array a
    a = list(map(int, input_data[1:]))
    
    if n == 0:
        print("NO")
        return

    # KMP Failure Function
    pi = [0] * n
    for i in range(1, n):
        j = pi[i-1]
        while j > 0 and a[i] != a[j]:
            j = pi[j-1]
        if a[i] == a[j]:
            j += 1
        pi[i] = j

    len_longest_prefix_suffix = pi[n-1]
    l = n - len_longest_prefix_suffix

    if len_longest_prefix_suffix > 0 and n % l == 0:
        print("YES")
    else:
        print("NO")

if __name__ == '__main__':
    solve()
```

### Flag

`HTB{3t3rn4l_sh1nju_p4tt3rn}`
