from math import *
import gmpy

def fermat_factor(N):
    """
    Guess at a and hope that a^2 - N = b^2,
    which is the case if p and q is "too close".
    """
    a  = gmpy.sqrt(N)
    b2 = a*a - N
    while not gmpy.is_square(gmpy.mpz(b2)):
        b2 += 2*a + 1
        a  += 1

    factor1 = a - gmpy.sqrt(b2)
    factor2 = a + gmpy.sqrt(b2)
    return (int(factor1.digits()),int(factor2.digits()))

def totient(p,q):
    """Eulers totient function"""
    return (p-1)*(q-1)

def egcd(a, b):
    """Extended greatest common denominator function"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Modular multiplicative inverse, i.e. aa^-1 = 1 (mod m)"""
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def calculate_private_key(p,q,e):
    """Calculate the private key, d, based on p, q, and e."""
    return modinv(e,totient(p,q))


def fast_exponentiation(a, p, n):
    """A fast way to calculate a**p % n"""
    result = a%n
    remainders = []
    while p != 1:
        remainders.append(p & 1)
        p = p >> 1
    while remainders:
        rem = remainders.pop()
        result = ((a ** rem) * result ** 2) % n
    return result

def int2bytes(n):
    """PKCS#1 integer to bytes conversion, as used by RSA"""
    string = ""
    while n > 0:
        string = "%s%s" % (chr(n & 0xFF), string)
        n /= 256
    return string

def bytes2int(bytes):
    """PKCS#1 bytes to integer conversion, as used by RSA"""
    integer = 0
    for byte in bytes:
        integer *= 256
        if isinstance(byte,str): byte = ord(byte)
        integer += byte
    return integer

def decrypt(c,d,n):
    """
    Given an encrypted number, c, and the private key, n and d,
    returns plaintext number m.
    """
    return fast_exponentiation(c,d,n)

def encrypt(m,e,n):
    """
    Given a plaintext number, m, and the public key, e and n,
    returns the encrypted number c.
    """
    return fast_exponentiation(m,e,n)
