"""
CTF challenges are sometimes guarded by Proof of Work (PoW) challenges. These
challenges require a connecting host to perform computational effort. Guarding
a service with a Proof of Work challenge slows down the rate at which a user
can connect to a service, reducing the effectiveness of brute-force techniques.

Different Proof of Work algorithms require the connecting host to perform
different operations. The algorithms are not interoperable. You must choose the
correct algorithm to satisfy the server's requirements. As a connecting user,
you are normally told which Proof of Work algorithm is in use by the server.

Pwntools provides an implementation of Google's kCTF Proof of Work algorithm.
"""

from pwnlib.data.kctf.pow import solve_challenge as _kctf_pow_solve_challenge, \
    verify_challenge as _kctf_pow_verify_challenge, get_challenge as _kctf_get_challenge


def kctf_pow_solve(challenge):
    """
    Solve a kCTF Proof of Work challenge

    Arguments:
      `challenge` (str): The challenge to solve

    Returns:
      A string representing an acceptable solution

    >>> challenge = 's.AAAB.AAAvm89LbEt4meEnXGwbHp3z'
    >>> kctf_pow_solve(challenge)[:20] + '...'
    's.AAAo8s+2Q06cSBM4nf...'
    >>> hashes.sha256sumhex(six.ensure_binary(kctf_pow_solve(challenge)))
    'fd13e60761fb4119848f2d7704100f8737c0ed754ef90f573cff74faac8ca800'

    >>> kctf_pow_verify(challenge, kctf_pow_solve(challenge))
    True
    """
    return _kctf_pow_solve_challenge(challenge)


def kctf_pow_verify(challenge, solution):
    """
    Verify a kCFT Proof of Work solution

    Arguments:
      `challenge` (str): The challenge that was solved
      `solution` (str): The solution to verify

    Returns:
      True if the solution is acceptable, else False

    >>> challenge1 = kctf_pow_generate_challenge(1)
    >>> challenge2 = kctf_pow_generate_challenge(1)
    >>> kctf_pow_verify(challenge1, kctf_pow_solve(challenge1))
    True

    >>> kctf_pow_verify(challenge1, kctf_pow_solve(challenge2))
    False
    """
    return _kctf_pow_verify_challenge(challenge, solution, False)


def kctf_pow_generate_challenge(difficulty):
    """
    Generate a kCTF Proof of Work challenge

    Arguments:
      `difficulty` (int): The challenge difficulty. A difficulty of 31337 can be solved in ~30 seconds
        at 1.66GHz with gmpy2 installed

    Returns:
      A string representing the challenge
    """
    return _kctf_get_challenge(difficulty)