from sympy import randprime
from random import randint

def randomprimegenerator(bits):
    lower_bound = 2**(bits - 1)
    upper_bound = 2**bits - 1
    prime = randprime(lower_bound, upper_bound)
    return prime

def extendedeuclidean(a, b):
    if b == 0:
        return a, 1, 0
    else:
        x2, x1, y2, y1 = 1, 0, 0, 1
        r = 0
        while b > 0:
            q = a // b
            r = a - q * b
            x = x2 - q * x1
            y = y2 - q * y1
            a, b = b, r
            x2, x1 = x1, x
            y2, y1 = y1, y
        return a, x2, y2

def encryptionkeygenerator(phi):
    while True:
        e = randint(2, phi - 1)
        gcd, _, _ = extendedeuclidean(e, phi)
        if gcd == 1:
            break
    return e

def keygenerator():
    p = randomprimegenerator(1024)
    q = randomprimegenerator(1024)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = encryptionkeygenerator(phi)
    d = extendedeuclidean(e, phi)[1] % phi

    return (e, n), (d, n)

if __name__ == "__main__":
    public_key, private_key = keygenerator()
    print("Public Key:", public_key)
    print("Private Key:", private_key)
    print("e:", public_key[0])
    print("d:", private_key[0])

