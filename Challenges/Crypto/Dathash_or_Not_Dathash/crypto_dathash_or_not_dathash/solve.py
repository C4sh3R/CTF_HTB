import sys
from fpylll import IntegerMatrix, LLL
from Crypto.Util.number import long_to_bytes

# Increase integer string conversion limit just in case
sys.set_int_max_str_digits(50000)

class Polynomial:
    def __init__(self, coeffs):
        # coeffs[i] is coefficient of x^i
        self.coeffs = coeffs

    def degree(self):
        return len(self.coeffs) - 1

    def __add__(self, other):
        max_len = max(len(self.coeffs), len(other.coeffs))
        new_coeffs = [0] * max_len
        for i in range(max_len):
            a = self.coeffs[i] if i < len(self.coeffs) else 0
            b = other.coeffs[i] if i < len(other.coeffs) else 0
            new_coeffs[i] = a + b
        return Polynomial(new_coeffs)

    def __mul__(self, other):
        if isinstance(other, int):
            return Polynomial([c * other for c in self.coeffs])
        
        deg1 = self.degree()
        deg2 = other.degree()
        new_coeffs = [0] * (deg1 + deg2 + 1)
        for i in range(len(self.coeffs)):
            for j in range(len(other.coeffs)):
                new_coeffs[i+j] += self.coeffs[i] * other.coeffs[j]
        return Polynomial(new_coeffs)

    def shift(self, k):
        # Multiply by x^k
        return Polynomial([0]*k + self.coeffs)

    def evaluate(self, x):
        res = 0
        for i, c in enumerate(self.coeffs):
            res += c * (x**i)
        return res

def find_integer_root(coeffs):
    # coeffs: [c_k, ..., c_1, c_0] for c_k x^k + ...
    # Binary search for root
    def f(x):
        res = 0
        for c in coeffs:
            res = res * x + c
        return res
    
    # Bound
    low = 0
    high = 2**2000
    
    # Check signs
    v_low = f(low)
    v_high = f(high)
    
    if v_low == 0: return low
    if v_high == 0: return high
    
    if v_low * v_high > 0:
        # Try Newton
        x = 2**1500
        for _ in range(100):
            val = f(x)
            if val == 0: return x
            # deriv
            deriv = 0
            deg = len(coeffs) - 1
            for i, c in enumerate(coeffs[:-1]):
                # term is c * x^(deg-i)
                # deriv is c * (deg-i) * x^(deg-i-1)
                p = deg - i
                deriv = deriv * x + c * p
            
            if deriv == 0: break
            x = x - val // deriv
        return None

    while high - low > 1:
        mid = (low + high) // 2
        v_mid = f(mid)
        if v_mid == 0:
            return mid
        if v_mid * v_low > 0:
            low = mid
            v_low = v_mid
        else:
            high = mid
            v_high = v_mid
            
    return None

def solve():
    # Read values
    data = {}
    with open('output.txt', 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split(' = ')
                data[key] = int(value)

    n0 = data['n0']
    c0 = data['c0']
    n1 = data['n1']
    c1 = data['c1']
    n2 = data['n2']
    c2 = data['c2']

    a = 2**2025

    # CRT
    N = n0 * n1 * n2
    N0 = N // n0
    N1 = N // n1
    N2 = N // n2

    u0 = pow(N0, -1, n0)
    u1 = pow(N1, -1, n1)
    u2 = pow(N2, -1, n2)

    # Construct P(y) for y = M (original message)
    # P(y) = y^3 + C2*y^2 + C1*y + C0
    # mod n0: (y+a)^3 - c0 = y^3 + 3a*y^2 + 3a^2*y + a^3 - c0
    # mod n1: (y+2a)^3 - c1 = y^3 + 6a*y^2 + 12a^2*y + 8a^3 - c1
    # mod n2: (y+3a)^3 - c2 = y^3 + 9a*y^2 + 27a^2*y + 27a^3 - c2

    coeff_3 = 1
    
    # C2
    # 3a, 6a, 9a
    coeff_2 = (3*a * N0 * u0 + 6*a * N1 * u1 + 9*a * N2 * u2) % N
    
    # C1
    # 3a^2, 12a^2, 27a^2
    coeff_1 = (3*a**2 * N0 * u0 + 12*a**2 * N1 * u1 + 27*a**2 * N2 * u2) % N
    
    # C0
    # a^3-c0, 8a^3-c1, 27a^3-c2
    coeff_0 = ((a**3 - c0) * N0 * u0 + (8*a**3 - c1) * N1 * u1 + (27*a**3 - c2) * N2 * u2) % N

    P = Polynomial([coeff_0, coeff_1, coeff_2, coeff_3])

    # Lattice parameters
    # m=2, d=9
    X = 2**1510
    
    basis_polys = []
    
    # Group 1: N^2 x^j
    N2_val = N*N
    for j in range(3):
        basis_polys.append(Polynomial([0]*j + [N2_val]))
        
    # Group 2: N P x^j
    NP = P * N
    for j in range(3):
        basis_polys.append(NP.shift(j))
        
    # Group 3: P^2 x^j
    P2 = P * P
    for j in range(3):
        basis_polys.append(P2.shift(j))
        
    # Construct matrix
    # Dimension 9
    dim = 9
    
    # fpylll IntegerMatrix(rows, cols)
    M = IntegerMatrix(dim, dim)
    
    for row_idx, poly in enumerate(basis_polys):
        for col_idx in range(dim):
            if col_idx < len(poly.coeffs):
                # We need to scale by X^col_idx
                val = poly.coeffs[col_idx] * (X**col_idx)
                M[row_idx, col_idx] = int(val)
                
    print("Running LLL with fpylll...")
    LLL.reduction(M)
    
    # Check all vectors
    for row_idx in range(dim):
        v = M[row_idx]
        
        # Reconstruct polynomial
        coeffs = []
        for i in range(dim):
            coeffs.append(int(v[i]) // (X**i))
            
        # Reverse for root finding (highest degree first)
        coeffs_rev = coeffs[::-1]
        
        # Skip if constant
        if all(c == 0 for c in coeffs_rev[:-1]):
            continue
            
        print(f"Checking vector {row_idx}...")
        root = find_integer_root(coeffs_rev)
        if root:
            print(f"Found root: {root}")
            try:
                print(f"Flag: {long_to_bytes(root)}")
                return
            except:
                print("Could not convert to bytes")

    print("Root not found")

if __name__ == "__main__":
    solve()
