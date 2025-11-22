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
    
    # Process remaining elements
    # We can iterate through the rest of the iterator directly
    # But we should be careful if there are extra tokens (though unlikely for single test case)
    # We can just loop n times
    
    for _ in range(n):
        try:
            x = int(next(iterator))
            if not tails or x > tails[-1]:
                tails.append(x)
            else:
                idx = bisect_left(tails, x)
                tails[idx] = x
        except StopIteration:
            break
            
    print(len(tails))

if __name__ == '__main__':
    solve()
