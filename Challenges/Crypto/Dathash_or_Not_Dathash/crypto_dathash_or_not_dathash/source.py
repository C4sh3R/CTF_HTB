from Crypto.Util.number import isPrime, getPrime, bytes_to_long
import os
from secret import e, FLAG

nb_padding_bits = 1500 - 8*len(FLAG)
message = FLAG + os.urandom(nb_padding_bits // 8)
m = bytes_to_long(message)

class RSA:
    def __init__(self, bits):
        p = getPrime(bits//2)
        q = getPrime(bits//2)
        self.n = p * q
        assert isPrime(e - 1) and isPrime(e)
    
    def encrypt(self, m):
        return pow(m, e, self.n)

with open('output.txt','w') as f:
    for i in range(3):
        rsa = RSA(2048)
        c = rsa.encrypt(m := m + 2**2025)

        f.write(f"n{i} = {rsa.n}\n")
        f.write(f"c{i} = {c}\n")
