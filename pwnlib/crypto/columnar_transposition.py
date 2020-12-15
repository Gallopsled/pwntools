# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/columnar_transposition.py

class cipher_columnar_transposition:
    def __dec(self, alphabet, key, text):
        chars = [alphabets.get_index_in_alphabet(char, alphabet)
                 for char in key]
        keyorder = sorted(enumerate(chars), key=lambda x: x[1])
        ret = u""
        rows = int(len(text) / len(key))

        cols = [0] * len(key)
        for i, item in enumerate(range(0, len(text), rows)):
            cols[keyorder[i][0]] = text[item: item + rows]

        for j in range(rows):
            for i in range(len(cols)):
                ret += cols[i][j]
        return ret

    def __enc(self, alphabet, key, text):
        # add endings to the text to fill the square
        rmd = len(text) % len(key)
        if rmd != 0:
            text += alphabet[-1] * (len(key) - rmd)

        chars = [alphabets.get_index_in_alphabet(char, alphabet)
                 for char in key]
        keyorder1 = sorted(enumerate(chars), key=lambda x: x[1])

        ret = u""
        for i in range(len(key)):
            ret += text[keyorder1[i][0]::len(key)]

        return ret

    def encrypt(self, text, key, alphabet=None):
        alphabet = alphabet or alphabets.ENGLISH
        return self.__enc(alphabet, key, text)

    def decrypt(self, text, key, alphabet=None):
        alphabet = alphabet or alphabets.ENGLISH
        return self.__dec(alphabet, key, text)
