import signal
from pwn import log
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

def crack_rsa(n,e = None,c = None):
    log.info("Cracking RSA key")
    log.waitfor("Trying Fermat factorization...")

    try:
        (p,q) = fermat_factor(n)
        log.succeeded("success!")
        log.success("p = %d" % p)
        log.success("q = %d" % q)
        if e != None:
            d = calculate_private_key(p,q,e)
            log.success("d = %d" % d)
            if c != None:
                log.info("Possible message: %s" % int2bytes(decrypt(c,d,n)))
    except TimeoutError:
        log.failed("failed")
