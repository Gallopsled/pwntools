import heapq
import string
from pwn import flat
from math import ceil
from numpy import mean
import matplotlib.pyplot as plt

import util
import freq
import monoalphabetic

#####################################
# GENERAL CALCULATION OF KEY PERIOD #
#####################################

def strandScores(strands, cutoff=0.06):
    scores = []
    for strand in strands:
        score = util.indexOfCoincidence(freq.count(strand), len(strand))
        scores.append( (score, strand) )
    return scores

def keyPeriod(guesses, cutoff=0.06):
    fitness = []
    for (length, strands) in guesses:
        scores = strandScores(strands, cutoff)
        fitness.append( (length, mean([score for score,_ in scores])) )

    if cutoff == None: return fitness
    else: return filter(lambda (length, score): score > cutoff, fitness)

def graphKeyPeriod(ciphertext, splitFunction, limit = None, cutoff=0.06):
    if limit == None: limit = min((len(ciphertext) / 2) + 1, 20)
    else: limit = limit + 1

    filtered = filter(lambda c: c in string.letters, ciphertext)
    guesses = [splitFunction(filtered, period) for period in range(1, limit)]
    fitness = keyPeriod(guesses, None)

    periods = [period for period, _ in fitness]
    scores = [score for _, score in fitness]
    colors = ['red' if score > cutoff else 'gray' for _, score in fitness]

    fig = plt.figure()
    ax = fig.add_subplot(111)
    rects = ax.bar(periods, scores, align='center', color=colors)

    ax.set_ylabel("Index of coincidence")
    ax.set_xlabel("Key period")
    ax.set_xticks(periods)
    leg = ax.legend( rects, ("Below " + str(cutoff), "Above " + str(cutoff)))

    # Set the legend color for above cutoff values
    # to red, and make legend transparent
    patches = leg.get_patches()
    patches[0].set_facecolor('gray')
    patches[1].set_facecolor('red')
    leg.get_frame().set_alpha(0.5)

    plt.show()

###################################
# GENERAL ENCRYPTION / DECRYPTION #
###################################

def encrypt(plaintext, key, cipher, alphabet=string.uppercase):
    (split, interleave) = cipher
    (_, strands) = split(plaintext, len(key))
    ciphers = []
    for i in range(len(strands)):
        shift = alphabet.index(key[i])
        ciphers.append( monoalphabetic.encrypt(strands[i], monoalphabetic.shiftDict(shift, alphabet)) )
    return interleave(ciphers, len(plaintext))

def decrypt(ciphertext, key, cipher, alphabet=string.uppercase):
    (split, interleave) = cipher
    (_, strands) = split(ciphertext, len(key))
    ciphers = []
    for i in range(len(strands)):
        shift = alphabet.index(key[i])
        ciphers.append( monoalphabetic.decrypt(strands[i], monoalphabetic.shiftDict(shift, alphabet)) )
    return interleave(ciphers, len(ciphertext))

###################
# VIGENERE CIPHER #
###################

def splitVigenere(ciphertext, keylength):
    return (keylength, [ciphertext[i::keylength] for i in range(keylength)])

def interleaveVigenere(strands, length):
    return flat([[strand[n:n+1] for strand in strands] for n in range(length)])

vigenere = (splitVigenere, interleaveVigenere)

def crackVigenere(ciphertext, cutoff=0.06, alphabet=string.uppercase, frequencies=freq.english):
    limit = min((len(ciphertext) / 2) + 1, 20)
    guesses = [splitVigenere(ciphertext, period) for period in range(1, limit)]
    possible = keyPeriod(guesses, cutoff)
    results = []
    for (period, score) in possible:
        key = ""
        (length, ciphers) = splitVigenere(ciphertext, period)
        for i in range(len(ciphers)):
            (k,m) = monoalphabetic.crackShift(ciphers[i], alphabet, frequencies)
            key += alphabet[k]
            ciphers[i] = m
        result = (key, interleaveVigenere(ciphers, len(ciphertext)))
        results.append(result)
    return results
