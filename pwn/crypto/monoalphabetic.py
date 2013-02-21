import string
import operator
import collections
from fractions import gcd

import util
import frequencies

#################################
# GENERIC MONOALPHABETIC CIPHER #
#################################

def encrypt(plaintext, dictionary):
    alphabet = dictionary.keys()
    return "".join(map(lambda c: dictionary[c] if c in alphabet else c, plaintext))

def decrypt(ciphertext, dictionary):
    inverse = {v: k for k,v in dictionary.items()}
    return encrypt(ciphertext, inverse)

def crack(ciphertext, frequencies=frequencies.english):
    pass

def genericCrack(ciphertext, candidates, frequencies=frequencies.english):
    distances = []
    for candidate in candidates:
        trial = encrypt(ciphertext, candidate)
        freq = frequencies.text([c for c in trial if c in candidate.keys()])
        distances.append(Utilities.squaredDifferences(freq, frequencies))
    guess = distances.index(min(distances))
    return (candidates[guess], encrypt(ciphertext, candidates[guess]))

def crackShift(ciphertext, alphabet=string.uppercase, frequencies=frequencies.english):
    candidates = [shiftDict(i, alphabet) for i in range(len(alphabet))]
    (dictionary, plaintext) = genericCrack(ciphertext, candidates, frequencies)
    shift = (key for key,value in dictionary.items() if value == alphabet[0]).next()
    return (alphabet.index(shift), plaintext)

def crackAffine(ciphertext, alphabet=string.uppercase, frequencies=frequencies.english):
    n = len(alphabet)
    invertible = [i for i in range(n) if gcd(i,n) == 1]
    keys = [(a,b) for a in invertible for b in range(n)]
    candidates = [affineDict(k) for k in keys]
    return genericCrack(ciphertext, candidates, frequencies)

############################
# SPECIFIC IMPLEMENTATIONS #
############################

def shiftDict(shift=3, alphabet=string.uppercase):
    return affineDict((1,shift), alphabet)

def affineDict(key, alphabet=string.uppercase):
    (a, b) = key
    n = len(alphabet)
    return {alphabet[i]: alphabet[(a * i + b) % n] for i in range(n)}

def atbashDict(alphabet=string.uppercase):
    n = len(alphabet)
    return affineDict((n - 1, n - 1), alphabet)
