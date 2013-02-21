import string
import collections
from itertools import *

import Frequencies

def indexOfCoincidence(frequencies, n):
    combinations = sum([f * (f - 1) for f in frequencies.values()])
    pairs = n * (n - 1)
    return float(combinations) / float(pairs) if pairs > 0 else 0

def expectedIC(frequencies):
    return sum([f * f for f in frequencies.values()])

def squaredDifferences(frequencies, expected):
    pairs = zip(frequencies.values(), expected.values())
    return sum([(f - e) ** 2 for f,e in pairs])

def chiSquared(counts, length, expected=Frequencies.english):
    expectedcount = {c: e * length for c,e in expected.items()}
    pairs = zip(counts.values(), expected.values())
    return sum([((c - e) ** 2) / float(e) for c,e in pairs])

