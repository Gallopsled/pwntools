"""
Utilities for working with monoalphabetic ciphers.
Includes tools for cracking several well-known ciphers.
"""

import string

import pwn
import util
import freq
import ngram

#################################
# GENERIC MONOALPHABETIC CIPHER #
#################################

def encrypt_substitution(plaintext, dictionary):
    """
    Encrypt a plaintext using a substitution cipher.

    Args:
        plaintext: the text to encrypt.
        dictionary: the replacement table for symbols in the plaintext.

    Returns:
        the plaintext encrypted using the replacement dictionary specified.
    """
    alphabet = dictionary.keys()
    return "".join(map(lambda c: dictionary[c] if c in alphabet else c, plaintext))

def decrypt_substitution(ciphertext, dictionary):
    """
    Decrypts a ciphertext using a substitution cipher.

    Args:
        ciphertext: the ciphertext to decrypt.
        dictionay: the replacement table for symbols in the ciphertext.
                   WILL BE INVERTED, so specify the one that was used for encryption.

    Returns:
        the ciphertext decrypted using the replacement dictionary specified.
    """
    inverse = {v: k for k,v in dictionary.items()}
    return encrypt_substitution(ciphertext, inverse)

def crack_substitution(ciphertext, num_starts=20, num_iterations=3000, frequencies=freq.english, show_status=True):
    import random, heapq, sys
    global_best_dict = {}
    global_best_score = sys.float_info.max

    mixed_alphabet = list(string.uppercase)

    if show_status: pwn.log.waitfor("Cracking cipher")
    for i in range(num_starts):
        local_scores = []

        random.shuffle(mixed_alphabet)
        new_dict = {k:v for (k,v) in zip(string.uppercase, mixed_alphabet)}
        new_score = -1 * ngram.log_p(ciphertext.lower(), ngram.english_freq(3), 3)

        heapq.heappush(local_scores, (new_score, new_dict))

        for _ in range(num_iterations):
            (local_best__score, local_best_dict) = local_scores[0]
            new_dict = local_best_dict.copy()

            c1 = random.choice(string.uppercase)
            c2 = random.choice(string.uppercase)

            new_dict[c1], new_dict[c2] = new_dict[c2], new_dict[c1]

            trial = encrypt_substitution(ciphertext, new_dict)
            new_score = -1 * ngram.log_p(trial.lower(), ngram.english_freq(3), 3)

            heapq.heappush(local_scores, (new_score, new_dict))

        (local_best_score, local_best_dict) = local_scores[0]
        if local_best_score < global_best_score:
            global_best_score = local_best_score
            global_best_dict = local_best_dict
            if show_status: log.status(encrypt_substitution(ciphertext, global_best_dict))

    if show_status: log.succeeded(encrypt_substitution(ciphertext, global_best_dict))
    return (global_best_dict, encrypt_substitution(ciphertext, global_best_dict))


def generic_crack(ciphertext, candidates, frequencies=freq.english, alphabet=string.uppercase):
    distances = []
    for candidate in candidates:
        trial = encrypt_substitution(ciphertext, candidate)
        candidate_freq = freq.text(trial, alphabet)
        distances.append(util.squared_differences(candidate_freq, frequencies))
    guess = distances.index(min(distances))
    return (candidates[guess], encrypt_substitution(ciphertext, candidates[guess]))

#################
# AFFINE CIPHER #
#################

def _affine_dict(key, alphabet=string.uppercase):
    """
    Generate a Affine-cipher dictionary for use as a generic substitution cipher.

    Args:
        key: the Affine-cipher key specified in the format (a, b).
             the a-component must have a multiplicative inverse mod len(alphabet)
        alphabet: an alphabet of symbols that the plaintext consists of.

    Returns:
        a dictionary ready for use with the encrypt_substitution method.
    """
    (a, b) = key
    n = len(alphabet)
    return {alphabet[i]: alphabet[(a * i + b) % n] for i in range(n)}

def encrypt_affine(plaintext, key, alphabet=string.uppercase):
    """
    Encrypt a text using an Affine-cipher.

    Args:
        plaintext: the text to encrypt.
        key: the key to use for the cipher, in the format (a,b)
             the a-component must have a multiplicative inverse mod len(alphabet)
        alphabet: the alphabet of symbols that the cipher is defined over.
                  symbols not in the alphabet will be ignored.
    """
    return encrypt_substitution(plaintext, _affine_dict(key, alphabet))

def decrypt_affine(ciphertext, key, alphabet=string.uppercase):
    """
    Decrypt a text using an Affine-cipher.

    Args:
        ciphertext: the text to decrypt.
        key: the key to use for the cipher, in the format (a,b)
             the a-component must have a multiplicative inverse mod len(alphabet)
        alphabet: the alphabet of symbols that the cipher is defined over.
                  symbols not in the alphabet will be ignored.
    """
    return decrypt_substitution(ciphertext, _affine_dict(key, alphabet))

def crack_affine(ciphertext, alphabet=string.uppercase, frequencies=freq.english):
    """
    Crack an Affine-cipher using squared differences between frequency distributions.

    Args:
        ciphertext: the ciphertext to crack.
        alphabet: the alphabet of symbols that the ciphertext consists of.
                  symbols not in the alphabet will be ignored.
        frequencies: the target frequency distribution to compare against when cracking.

    Returns:
        #TODO: Return a tuple with the key, format (key, plaintext)
        the plaintext of the broken cipher.
    """
    from fractions import gcd
    n = len(alphabet)
    invertible = [i for i in range(n) if gcd(i,n) == 1]
    keys = [(a,b) for a in invertible for b in range(n)]
    candidates = [_affine_dict(k) for k in keys]
    return generic_crack(ciphertext, candidates, frequencies)

#################
# ATBASH CIPHER #
#################

def _atbash_dict(alphabet=string.uppercase):
    """
    Generate a Atbash-cipher dictionary for use as a generic substitution cipher.

    Args:
        alphabet: an alphabet of symbols that the plaintext consists of.

    Returns:
        a dictionary ready for use with the encrypt_substitution method.
    """
    n = len(alphabet)
    return _affine_dict((n - 1, n - 1), alphabet)

def encrypt_atbash(plaintext, alphabet=string.uppercase):
    """
    Encrypt a text using the Atbash cipher

    Args:
        plaintext: the text to encrypt.
        alphabet: the alphabet of symbols that the cipher is defined over.
                  symbols not in the alphabet will be ignored.
    """
    return encrypt_substitution(plaintext, _atbash_dict(alphabet))

def decrypt_atbash(ciphertext, alphabet=string.uppercase):
    """
    Decrypt a text using the Atbash cipher.
    Here for completeness, same as encrypting!

    Args:
        ciphertext: the text to decrypt.
        alphabet: the alphabet of symbols that the cipher is defined over.
                  symbols not in the alphabet will be ignored.
    """
    return encrypt_atbash(ciphertext, alphabet)

def crack_atbash(ciphertext, alphabet=string.uppercase):
    """
    "Crack" an Atbash cipher.
    Here for completeness, same as encrypting/decrypting!

    Args:
        ciphertext: the text to crack.
        alphabet: the alphabet of symbols that the cipher is defined over.
                  symbols not in the alphabet will be ignored.
    """
    return encrypt_atbash(ciphertext, alphabet)

################
# SHIFT CIPHER #
################

def _shift_dict(shift=3, alphabet=string.uppercase):
    """
    Generate a Shift-cipher dictionary for use as a generic substitution cipher.

    Args:
        shift: the shift to apply to symbols in the alphabet.
        alphabet: an alphabet of symbols that the plaintext consists of.

    Returns:
        a dictionary ready for use with the encrypt_substitution method.
    """
    return _affine_dict((1,shift), alphabet)

def encrypt_shift(plaintext, key, alphabet=string.uppercase):
    """
    Encrypt a text using a Shift-cipher.

    Args:
        plaintext: the text to encrypt.
        key: the shift to apply to the symbols in the text.
        alphabet: the alphabet of symbols that the cipher is defined over.
                  symbols not in the alphabet will be ignored.
    """
    return encrypt_substitution(plaintext, _shift_dict(key, alphabet))

def decrypt_shift(ciphertext, key, alphabet=string.uppercase):
    """
    Decrypt a text using a Shift-cipher.

    Args:
        ciphertext: the text to decrypt.
        key: the shift to apply to the symbols in the text.
        alphabet: the alphabet of symbols that the cipher is defined over.
                  symbols not in the alphabet will be ignored.
    """
    return decrypt_substitution(ciphertext, _shift_dict(key, alphabet))

def crack_shift(ciphertext, alphabet=string.uppercase, frequencies=freq.english):
    """
    Crack a Shift-cipher using squared differences between frequency distributions.

    Args:
        ciphertext: the ciphertext to crack.
        alphabet: the alphabet of symbols that the ciphertext consists of.
                  symbols not in the alphabet will be ignored.
        frequencies: the target frequency distribution to compare against when cracking.

    Returns:
        a tuple (k, p) consisting of the shift amount and the plaintext of the broken cipher.
    """
    candidates = [_shift_dict(i, alphabet) for i in range(len(alphabet))]
    (dictionary, plaintext) = generic_crack(ciphertext, candidates, frequencies, alphabet)
    shift = (key for key,value in dictionary.items() if value == alphabet[0]).next()
    return (alphabet.index(shift), plaintext)
