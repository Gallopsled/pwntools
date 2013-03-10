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

def strandScores(strands, ic_target=0.06):
    scores = []
    for strand in strands:
        score = util.indexOfCoincidence(freq.count(strand), len(strand))
        scores.append( (score, strand) )
    return scores

def keyPeriod(guesses, ic_target=0.06, prune = False):
    fitness = []
    for (length, strands) in guesses:
        scores = strandScores(strands, ic_target)
        fitness.append( (length, mean([score for score,_ in scores])) )

    if prune: return filter(lambda (length, score): score < ic_target / 10, fitness)
    else: return fitness

def graphKeyPeriod(ciphertext, splitFunction, limit = None, ic_target=0.065):
    if limit == None: limit = min((len(ciphertext) / 4) + 1, 20)
    else: limit = limit + 1

    filtered = filter(lambda c: c in string.letters, ciphertext)
    guesses = [splitFunction(filtered, period) for period in range(1, limit)]
    fitness = keyPeriod(guesses, ic_target)

    ic_deviation = ic_target * 0.10
    ic_upper = ic_target + ic_deviation
    ic_lower = ic_target - ic_deviation

    periods = [period for period, _ in fitness]
    scores = [score for _, score in fitness]
    colors = ['red' if score > ic_lower and score < ic_upper  else 'gray' for _, score in fitness]

    fig = plt.figure()
    ax = fig.add_subplot(111)
    rects = ax.bar(periods, scores, align='center', color=colors)

    ax.set_ylabel("Index of coincidence")
    ax.set_xlabel("Key period")
    ax.set_xticks(periods)
    leg = ax.legend( rects, ("Far from " + str(ic_target), "Close to " + str(ic_target)), loc='best' )

    # Label bars with value
    for i, rect in enumerate(rects):
        plt.text(rect.get_x() + rect.get_width()/2.0, 1.02 * rect.get_height(), "%.3f" % scores[i], ha="center")

    # Draw IC target lines line
    plt.axhline(ic_upper, color='gray', linestyle='--', zorder=-1)
    plt.axhline(ic_lower, color='gray', linestyle='--', zorder=-1)

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

def crackVigenere(ciphertext, ic_target=0.065, alphabet=string.uppercase, frequencies=freq.english):
    limit = int(len(ciphertext) / (len(alphabet) * 1.47)) # Unicity distance of english, TODO: Be able to change language
    guesses = [splitVigenere(ciphertext, period) for period in range(1, limit)]
    possible = keyPeriod(guesses, ic_target)
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
