# Dathash or Not Dathash - Writeup

## Challenge Info
- **Category:** Crypto
- **Difficulty:** Easy
- **Description:** Three mirrored tablets inscribed with divine equations...

## Analysis
The challenge provides the source code `source.py` and an output file `output.txt`.
The source code reveals:
1.  **RSA Encryption**: Standard RSA with $e=3$.
2.  **Message Structure**: $m = \text{bytes\_to\_long}(\text{FLAG} + \text{padding})$.
3.  **Broadcast**: The same message $m$ is encrypted 3 times with different moduli $n_0, n_1, n_2$.
4.  **Linear Padding**:
    - $c_0 = m^3 \pmod{n_0}$
    - $c_1 = (m + a)^3 \pmod{n_1}$ where $a = 2^{2025}$
    - $c_2 = (m + 2a)^3 \pmod{n_2}$

This is a variant of **Håstad's Broadcast Attack**. In the standard attack, the message is identical ($m^3 \pmod n_i$). Here, the message has a known linear relation.

## Solution
We can construct a polynomial $P(x)$ using the Chinese Remainder Theorem (CRT) such that $m$ is a root of $P(x)$ modulo $N = n_0 n_1 n_2$.

Let $N = n_0 n_1 n_2$.
We want to find $m$ such that:
- $m^3 \equiv c_0 \pmod{n_0}$
- $(m+a)^3 \equiv c_1 \pmod{n_1}$
- $(m+2a)^3 \equiv c_2 \pmod{n_2}$

Using CRT, we can combine these into a single polynomial $P(x)$ modulo $N$:
$$ P(x) \equiv \sum_{i=0}^{2} ((x + i \cdot a)^3 - c_i) \cdot N_i \cdot (N_i^{-1} \pmod{n_i}) \pmod N $$
where $N_i = N / n_i$.

Since $m < n_i$ and $e=3$, normally $m^3 < N$ and we could just take the integer cube root. However, because of the linear padding $a$, the terms $(m+ia)^3$ are larger. But $m$ itself is small (approx 1500 bits) compared to $N$ (approx 6000 bits).

We can use **Coppersmith's Method** (or lattice reduction) to find the small root $m$ of $P(x) \equiv 0 \pmod N$.

### Lattice Construction
We construct a lattice basis to find a small root $x_0$ for the monic polynomial $P(x)$.
We use the shift polynomials:
- $g_{i,j}(x) = N^{2-j} x^i P(x)^j$ ? No, simpler basis for $P(x) = 0 \pmod N$.

We used a lattice basis of dimension 9 involving polynomials:
- $N^2 x^j$ for $j=0,1,2$
- $N P(x) x^j$ for $j=0,1,2$
- $P(x)^2 x^j$ for $j=0,1,2$

We used `fpylll` to reduce this lattice and find the shortest vector, which corresponds to a polynomial over the integers that shares the root $m$. Solving this integer polynomial gives the flag.

## Flag
`HTB{h0w_t0_c0mb1n3_h4574d_b04rdc457_4nd_c0pp3rsm17h_4774ck}`
