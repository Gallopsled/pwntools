import string
import pwn

import util
import freq
import monoalphabetic as mono

#####################################
# GENERAL CALCULATION OF KEY PERIOD #
#####################################

def strand_scores(strands, alphabet=string.uppercase):
    """
    Calculate the index of coincidence of several texts.

    Args:
        strands: a list of the texts to calculate scores for.
        alphabet: the alphabet of symbols to use when calculating the index of coincidence.
                  symbols not in the alphabet will be ignored.

    Returns:
        a list of tuples of the form (score, strand).
    """
    scores = []
    for strand in strands:
        significant_length = len(filter(lambda c: c in alphabet, strand))
        score = util.index_of_coincidence(freq.count(strand, alphabet), significant_length)
        scores.append( (score, strand) )
    return scores

def key_period(guesses, ic_target=util.ic_english, alphabet=string.uppercase, prune = False, raw_score = False):
    """
    Score guesses on the key period of a ciphertext based on the distance between their
    index of coincidence and a target value. The distance is calculated from the mean
    of the scores of the individual text strands.

    Lower is better!

    Args:
        guesses: a list of guesses of the form (period_guess, [strands]).
                 where [strands] is a list containing the ciphertext split into period_guess
                 texts where the symbols of one text are encrypted under the same key.
        ic_target: the target index of coincidence used to assign a fitness score to the guesses.
        alphabet: the alphabet of symbols to use when calculating the index of coincidence.
                  symbols not in the alphabet will be ignored.
        prune: a boolean specifying if the results should be filtered to only contain results
               within 10% of the target index of coincidence.
        raw_score: do not calculate distance, instead return the raw index of coincidence

    Returns:
        a list of fitness scores of the form (length, mean_score).
    """
    from numpy import mean
    fitness = []
    for (length, strands) in guesses:
        scores = strand_scores(strands, alphabet)
        if not raw_score: fitness.append( (length, abs(ic_target - mean([score for score,_ in scores]))) )
        else: fitness.append( (length, mean([score for score,_ in scores])) )

    max_distance = ic_target / 10.0
    if prune: return filter(lambda (length, score): score < max_distance , fitness)
    else: return fitness

def choose_alphabet(ciphertext, alphabet):
    if alphabet is None:
        pwn.log.info('Trying to guess alphabet')
        ct = filter(lambda c: c in string.letters, ciphertext)
        if ct.isupper():
            pwn.log.success('Using uppercase letters')
            alphabet = string.uppercase
        elif ct.islower():
            pwn.log.success('Using lowercase letters')
            alphabet = string.lowercase
    if alphabet is None:
        raise TypeError('no alphabet')
    return alphabet

def graph_key_period(ciphertext, splitFunction, limit = None, ic_target=util.ic_english, alphabet=None):
    """
    Draw a graph of the index of coincidence scores of different key periods
    relative to a target index of coincidence.

    Args:
        ciphertext: the ciphertext to analyse.
        splitFunction: the function used to split the ciphertext into strands.
                       example: polyalphabetic.split_vigenere
        limit: user specified limit for key period guesses.
               if this is not given a sane default will be calculated based on the ciphertext.
        ic_target: the target index of coincidence used to assign a fitness score to the guesses.
        alphabet: the alphabet of symbols to use when calculating the index of coincidence.
                  symbols not in the alphabet will be ignored.

    Returns:
        draws a graph to the screen instead of returning anything.
    """
    import matplotlib.pyplot as plt
    alphabet = choose_alphabet(ciphertext, alphabet)

    if limit == None: limit = min((len(ciphertext) / 4) + 1, 20)
    else: limit = limit + 1

    filtered = filter(lambda c: c in string.letters, ciphertext)
    guesses = [splitFunction(filtered, period) for period in range(1, limit)]
    fitness = key_period(guesses, ic_target, alphabet, raw_score=True)

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
    plt.axhline(ic_upper, color='lightgray', linestyle='--', zorder=-1)
    plt.axhline(ic_target, color='gray', linestyle='--', zorder=-1)
    plt.axhline(ic_lower, color='lightgray', linestyle='--', zorder=-1)

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
        ciphers.append( mono.encrypt_substitution(strands[i], mono._shift_dict(shift, alphabet)) )
    return interleave(ciphers, len(plaintext))

def decrypt(ciphertext, key, cipher, alphabet=string.uppercase):
    (split, interleave) = cipher
    (_, strands) = split(ciphertext, len(key))
    ciphers = []
    for i in range(len(strands)):
        shift = alphabet.index(key[i])
        ciphers.append( mono.decrypt_substitution(strands[i], mono._shift_dict(shift, alphabet)) )
    return interleave(ciphers, len(ciphertext))

###################
# VIGENERE CIPHER #
###################

def split_vigenere(ciphertext, keylength):
    return (keylength, [ciphertext[i::keylength] for i in range(keylength)])

def interleave_vigenere(strands, length):
    return pwn.flat([[strand[n:n+1] for strand in strands] for n in range(length)])

vigenere_cipher = (split_vigenere, interleave_vigenere)

def crack_vigenere(ciphertext, known_period=None, ic_target=util.ic_english, alphabet=None, frequencies=freq.english):
    alphabet = choose_alphabet(ciphertext, alphabet)

    ct = filter(lambda c: c in alphabet, ciphertext)

    if known_period == None:
        limit = int(len(ct) / (len(alphabet) * 1.47)) # Unicity distance of english, TODO: Be able to change language
        guesses = [split_vigenere(ct, period) for period in range(1, limit)]
        possible = key_period(guesses, ic_target, alphabet)
    else: possible = [(known_period, 0)]

    results = []
    for (period, score) in possible:
        key = ""
        (length, ciphers) = split_vigenere(ct, period)
        for i in range(len(ciphers)):
            (k,m) = mono.crack_shift(ciphers[i], alphabet, frequencies)
            key += alphabet[k]
            ciphers[i] = m
        result = (key, interleave_vigenere(ciphers, len(ct)))
        results.append((score, result))

    def fixup((score, (key, pt))):
        out = ''
        j = 0
        for i in range(len(ciphertext)):
            if ciphertext[i] in alphabet:
                out += pt[j]
                j += 1
            else:
                out += ciphertext[i]
        return (score, (key, out))

    results = map(fixup, results)

    if len(results) == 1: return results[0][1]
    else: return [x[1] for x in sorted(results)]
