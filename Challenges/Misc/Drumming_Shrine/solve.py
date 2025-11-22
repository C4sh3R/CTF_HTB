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
    # Assuming single test case, the rest of the input is the array
    a = list(map(int, input_data[1:]))
    
    if len(a) != n:
        # Fallback if something is weird, but usually this is fine
        pass

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
