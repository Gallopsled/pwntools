import string, collections, os, signal
import gmpy
from functools import wraps
from itertools import *

import frequencies

#TODO: docstrings!
def indexOfCoincidence(frequencies, n):
    combinations = sum([f * (f - 1) for f in frequencies.values()])
    pairs = n * (n - 1)
    return float(combinations) / float(pairs) if pairs > 0 else 0

def expectedIC(frequencies):
    return sum([f * f for f in frequencies.values()])

def squaredDifferences(frequencies, expected):
    pairs = zip(frequencies.values(), expected.values())
    return sum([(f - e) ** 2 for f,e in pairs])

def chiSquared(counts, length, expected=frequencies.english):
    expectedcount = {c: e * length for c,e in expected.items()}
    pairs = zip(counts.values(), expected.values())
    return sum([((c - e) ** 2) / float(e) for c,e in pairs])

class TimeoutError(Exception):
    pass

# Timeout decorator
def timeout(seconds=10, error_message=""):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator

# Number theory
@timeout(10)
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

def gcd(b, p):
    """Greatest common denominator (Euclids algorithm)"""
    return egcd(b, p)[0]

def modinv(a, m):
    """Modular multiplicative inverse, i.e. a^-1 = 1 (mod m)"""
    a, u, v = egcd(a, m)
    if a <> 1:
        raise Exception('No inverse: %d (mod %d)' % (b, p))
    return u

def crt(a, n):
    """Solve Chinese remainder theorem, eg. determine x in
    a[0] = x       ( n[0] )
    ...
    a[-1] = x      ( n[-1] )

    Elements in n must be pairwise co-prime"""
    M = reduce(operator.mul, lm)
    # print M
    lM = [M/mi for mi in lm]
    ly = map(invmod, lM, lm)
    laMy = map((lambda ai, Mi, yi : ai*Mi*yi), la, lM, ly)
    return sum(laMy) % M

def reste_chinois(a, n):
    """Alias for crt"""
    return crt(a, n)

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

