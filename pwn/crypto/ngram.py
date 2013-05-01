from math import sqrt

def generate_ngram(text, n=3):
    occurences = ngram = dict()
    for i in range(len(text)):
        try:
            cur = text[i:i+n]
            if cur in occurences:
                occurences[cur] += 1
            else:
                occurences[cur] = 1
        except IndexError:
            pass

    for (key,value) in occurences.items():
        ngram[key] = float(value) / (len(text) - n + 1)

    return ngram

def dot(a,b):
    keys = set(a.keys()).union(set(b.keys()))
    sum = 0
    for i in keys:
        try:
            sum += a[i] * b[i];
        except KeyError:
            pass
    return sum

def norm(a):
    sum = 0
    for value in a.values():
      sum += value ** 2
    return sqrt(sum)

def cosine_similarity(a,b):
    return dot(a,b) / (norm(a) * norm(b))
