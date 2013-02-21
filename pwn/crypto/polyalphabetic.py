import heapq
import string
from pwn import flat
from math import ceil
from numpy import mean

import util
import frequencies
import monoalphabetic

#####################################
# GENERAL CALCULATION OF KEY PERIOD #
#####################################

def strandScores(strands, cutoff=0.06):
    scores = []
    for strand in strands:
        score = Utilities.indexOfCoincidence(frequencies.count(strand), len(strand))
        scores.append( (score, strand) )
    return scores

def keyPeriod(guesses, cutoff=0.06):
    fitness = []
    for (length, strands) in guesses:
        scores = strandScores(strands, cutoff)
        fitness.append( (length, mean([score for score,_ in scores])) )
    return filter(lambda (length, score): score > cutoff, fitness)

###################################
# GENERAL ENCRYPTION / DECRYPTION #
###################################

def encrypt(plaintext, key, cipher, alphabet=string.uppercase):
    (split, interleave) = cipher
    (_, strands) = split(plaintext, len(key))
    ciphers = []
    for i in range(len(strands)):
        shift = alphabet.index(key[i])
        ciphers.append( MonoAlphabetic.encrypt(strands[i], MonoAlphabetic.shiftDict(shift, alphabet)) )
    return interleave(ciphers, len(plaintext))

def decrypt(ciphertext, key, cipher, alphabet=string.uppercase):
    (split, interleave) = cipher
    (_, strands) = split(ciphertext, len(key))
    ciphers = []
    for i in range(len(strands)):
        shift = alphabet.index(key[i])
        ciphers.append( MonoAlphabetic.decrypt(strands[i], MonoAlphabetic.shiftDict(shift, alphabet)) )
    return interleave(ciphers, len(ciphertext))

###################
# VIGENERE CIPHER #
###################

def splitVigenere(ciphertext, keylength):
    return (keylength, [ciphertext[i::keylength] for i in range(keylength)])

def interleaveVigenere(strands, length):
    return flat([[strand[n:n+1] for strand in strands] for n in range(length)])

vigenere = (splitVigenere, interleaveVigenere)

def vigenereCrack(ciphertext, cutoff=0.06, alphabet=string.uppercase, frequencies=frequencies.english):
    limit = min((len(ciphertext) / 2) + 1, 20)
    guesses = [splitVigenere(ciphertext, period) for period in range(1, limit)]
    possible = keyPeriod(guesses, cutoff)
    results = []
    for (period, score) in possible:
        key = ""
        (length, ciphers) = splitVigenere(ciphertext, period)
        for i in range(len(ciphers)):
            (k,m) = MonoAlphabetic.crackShift(ciphers[i], alphabet, frequencies)
            key += alphabet[k]
            ciphers[i] = m
        result = (key, interleaveVigenere(ciphers, len(ciphertext)))
        results.append(result)
    return results
