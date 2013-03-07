import string
import collections
from itertools import *

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
    n = len(alphabet)
    return dict(zip(alphabet, [1.0 / n] * n))

def text(string, alphabet=string.uppercase):
    n = len(alphabet)
    freq = collections.defaultdict(float)
    for c in string: freq[c] += 1.0
    for c in alphabet: freq[c] /= n
    return freq

def count(string):
    return collections.Counter(string)
