import pwn
from util import *

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

def calculate_private_key(p,q,e):
    """Calculate the private key, d, based on p, q, and e."""
    return modinv(e,totient(p,q))

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

def wieners_attack(n, e):
    """
    Implements wieners attack on RSA.
    Based on http://wwwusers.di.uniroma1.it/~parisi/Risorse/Wiener_Attack.pdf
    """
    from sympy.solvers import solve
    from sympy.core import numbers
    from sympy import Symbol
    fractions = continued_fractions(n, e)
    for i in range(2, len(fractions)):
        frac = calculate_fraction(fractions[:i]).limit_denominator()
        t, a = frac._numerator, frac._denominator
        x = Symbol('x')
        (f1, f2) = solve(a*e - t*(x-1)*((n/x)-1) - 1, x)
        if isinstance(f1, numbers.Integer) and isinstance(f2, numbers.Integer):
            return (f1, f2)
    return None

def crack_rsa(n,e = None,c = None):
    """
    Tries all currently implemented attacks on RSA key.
    """
    pwn.log.info("Cracking RSA key")

    # Wieners attack
    if e != None:
        pwn.log.waitfor("Trying Wiener's attack")
        res = wieners_attack(n,e)
        if res != None:
            pwn.log.succeeded("success!")
            pwn.log.success("Factors: %d %d" % res)
            return
    else:
        pwn.log.failed()

    # Factor
    pwn.log.waitfor("Trying to factor...")
    res = factor(n)
    if res != None:
        p, q = res
        pwn.log.succeeded("success!")
        pwn.log.success("Factors: %d %d" % (p, q))
        if e != None:
            d = calculate_private_key(p,q,e)
            pwn.log.success("d = %d" % d)
            if c != None:
                pwn.log.info("Possible message: %s" % int2bytes(decrypt(c,d,n)))
        return
    else:
        pwn.log.failed("failed")

