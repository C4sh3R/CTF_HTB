import requests
import json

url = "http://154.57.164.71:30277/run"
code = """import sys
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
                idx = bisect_left(tails, x)
                tails[idx] = x
        except StopIteration:
            break
            
    print(len(tails))

if __name__ == '__main__':
    solve()
"""

payload = {
    "code": code,
    "language": "python"
}

try:
    response = requests.post(url, json=payload)
    print(response.text)
except Exception as e:
    print(e)
