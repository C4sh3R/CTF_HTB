# Fivefold Door

## Information

- **Difficulty**: Medium
- **Category**: Misc
- **Platform**: HackTheBox
- **Date**: November 21, 2025
- **Points**: 875

## Challenge Description

"Beneath Ishigaki-tori, the Fivefold Door sleeps—its stone crowded with the beasts of old clans, carved out of order by time and ruin. Only a rising cadence of strength will wake the seal: each sigil stronger than the last. You hold the full sequence. Find the longest ascent the door will still recognize—before the echo fades."

The challenge asks us to find the length of the **Longest Strictly Increasing Subsequence (LIS)** of a given sequence of integers.

**Input Format:**
- First line: Integer $N$ (number of sigils).
- Second line: $N$ integers $a_1, a_2, \dots, a_n$.

**Output Format:**
- A single integer: the length of the LIS.

**Constraints:**
- $2 \le N \le 10^6$
- $0 \le a_i \le 10^9$

## Reconnaissance

### Analysis

The problem is a classic algorithmic problem: finding the length of the Longest Increasing Subsequence (LIS).
A naive dynamic programming approach takes $O(N^2)$ time, which is too slow given $N \le 10^6$.
We need an $O(N \log N)$ solution.

The optimal approach maintains an array `tails`, where `tails[i]` stores the smallest ending element of all increasing subsequences of length `i+1` found so far.
The `tails` array is always sorted.
For each element `x` in the input sequence:
1. If `x` is larger than all elements in `tails`, it can extend the longest increasing subsequence found so far. We append `x` to `tails`.
2. If `x` is not larger than all elements, it can replace an existing element in `tails` to form a valid increasing subsequence of the same length but with a smaller ending element (which is better for future extensions). We find the smallest element in `tails` that is greater than or equal to `x` and replace it with `x`.

Since `tails` is sorted, we can use binary search (`bisect_left` in Python) to find the replacement position in $O(\log N)$ time.
The total time complexity is $O(N \log N)$.

## Exploitation

### Solution

I implemented the solution in Python using the `bisect` module.

```python
import sys
from bisect import bisect_left

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

    tails = []
    
    for _ in range(n):
        try:
            x = int(next(iterator))
            if not tails or x > tails[-1]:
                tails.append(x)
            else:
                # Find the first element >= x
                idx = bisect_left(tails, x)
                tails[idx] = x
        except StopIteration:
            break
            
    print(len(tails))

if __name__ == '__main__':
    solve()
```

### Flag

`HTB{LIS_0f_th3_f1v3}`
