import sys

def solve():
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
            # Each fold doubles the number of soldiers.
            # N * 2^K is equivalent to N << K
            ans = n << k
            results.append(str(ans))
        except StopIteration:
            break
    
    print('\n'.join(results))

if __name__ == '__main__':
    solve()
