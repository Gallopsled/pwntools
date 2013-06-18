import string
from itertools import *

# The expected frequency distribution for English text
english = {
    'A' : 0.082,
    'B' : 0.015,
    'C' : 0.028,
    'D' : 0.043,
    'E' : 0.126,
    'F' : 0.022,
    'G' : 0.020,
    'H' : 0.061,
    'I' : 0.070,
    'J' : 0.002,
    'K' : 0.008,
    'L' : 0.040,
    'M' : 0.024,
    'N' : 0.067,
    'O' : 0.075,
    'P' : 0.019,
    'Q' : 0.001,
    'R' : 0.060,
    'S' : 0.063,
    'T' : 0.091,
    'U' : 0.028,
    'V' : 0.010,
    'W' : 0.023,
    'X' : 0.001,
    'Y' : 0.020,
    'Z' : 0.001
}

def uniform(alphabet=string.uppercase):
    """
    Generate a uniform frequency distribution table for an alphabet.

    Args:
        alphabet: the alphabet to generate the frequency distribution for.

    Returns:
        a uniform frequency distribution over the alphabet.
    """
    n = len(alphabet)
    return dict(zip(alphabet, [1.0 / n] * n))

def text(string, alphabet=string.uppercase):
    """
    Calculate the frequency distribution of a piece of text over
    a specified alphabet.

    Args:
        string: the text string to calculate the frequency distribution of
        alphabet: the alphabet to use when calculating the frequency distribution.
                  symbols not in the alphabet will be ignored.

    Returns:
        the frequency distribution for the text string over the target alphabet.
    """
    import collections
    n = len(alphabet)
    freq = collections.defaultdict(float)
    for c in string:
        if c in alphabet: freq[c] += 1.0
    for c in alphabet: freq[c] /= n
    return freq

def count(string, alphabet=string.uppercase):
    """
    Count the number of occurrences of the different symbols present in a string.

    Args:
        string: the text to count symbols in.
        alphabet: the alphabet to use when calculating the frequency distribution.
                  symbols not in the alphabet will be ignored.

    Returns:
        a count of the different symbols in the text.
    """
    import collections
    string = filter(lambda c: c in alphabet, string)
    return collections.Counter(string)
