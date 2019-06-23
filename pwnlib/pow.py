"""
Brute force part of a hash until some expected value is found.

Example:
    pow.md5('00000', prefix='salt')

    This will try

      md5('salt' + n)
      md5('salt' + (n+1))
      md5('salt' + (n+2))
      md5('salt' + (n+3))

    until an md5 hash beginning with '00000' is discovered. It then returns the
    nonce needed to compute the hash.

    >>> proof_of_work(hashlib.md5, '0000', prefix='foo', suffix='bar', seed=0)
    11964
    >>> hashlib.md5(('foo' + str(11964) + 'bar').encode()).hexdigest()[:4]
    '0000'
"""
import hashlib
import random


def proof_of_work(hash, expected, prefix='', suffix='', seed=None):
    """
    >>> proof_of_work(hashlib.sha1, '0000', prefix='foo', seed=0)
    9591
    """
    expected = expected.lower()
    computed = None
    if seed is not None:
        nonce = seed
    else:
        nonce = random.randint(0, 1000000000)

    while computed != expected:
        nonce += 1
        computed = hash((prefix + str(nonce) + suffix).encode()
                        ).hexdigest()[:len(expected)]

    return nonce


def md5(expected, **kwargs):
    """
    >>> md5('0000', prefix='foo', seed=0)
    2027
    """
    return proof_of_work(hashlib.md5, expected, **kwargs)


def sha1(expected, **kwargs):
    """
    >>> sha1('0000', prefix='foo', seed=0)
    9591
    """
    return proof_of_work(hashlib.sha1, expected, **kwargs)


def sha256(expected, **kwargs):
    """
    >>> sha256('0000', prefix='foo', seed=0)
    76187
    """
    return proof_of_work(hashlib.sha256, expected, **kwargs)


def sha512(expected, **kwargs):
    """
    >>> sha512('0000', prefix='foo', seed=0)
    7317
    """
    return proof_of_work(hashlib.sha512, expected, **kwargs)
