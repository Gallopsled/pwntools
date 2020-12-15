# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/vic.py

class cipher_vic:
    def __find_index_in_alphabet(self, char, alphabet):
        for j in range(len(alphabet)):
            try:
                alphabet[j].index(char)
                break
            except ValueError:
                pass
        return j

    def __encDec(self, alphabet, text, key, do_encrypt):
        columns = []
        width = 10
        # define columns with null string
        for i, value in enumerate(alphabet):
            if value == "":
                columns.append(i)

        # encode chars to numbers
        code = ""
        for char in text:
            j = self.__find_index_in_alphabet(char, alphabet)
            row = int(j / width)
            if row > 0:
                column = j % width
                code += str(columns[row-1]) + str(column)
            else:
                code += str(j)

        enc = ""
        if do_encrypt:
            # addition by key
            for i in range(0, len(code)):
                enc += str((int(code[i]) + int(key[i % len(key)])) % 10)
        else:
            # subraction by key
            for i in range(0, len(code)):
                enc += str((int(code[i]) - int(key[i % len(key)])) % 10)

        # encode numbers to chars
        enc2 = ""
        row = 0
        for i in range(0, len(enc)):
            if row == 0 and (int(enc[i]) in columns):
                row = columns.index(int(enc[i])) + 1
            else:
                enc2 += alphabet[row * width + int(enc[i])][0]
                row = 0
        return enc2

    def encrypt(self, text, key=None, alphabet=None):
        alphabet = alphabet or [
            u"a", u"b", u"c", u"d", u"e",
            u"f", u"g", u"h", u"ij", u"k",
            u"l", u"m", u"n", u"o", u"p",
            u"q", u"r", u"s", u"t", u"u",
            u"v", u"w", u"x", u"y", u"z"
        ]
        return self.__encDec(alphabet, text, key, True)

    def decrypt(self, text, key=None, alphabet=None):
        alphabet = alphabet or [
            u"a", u"b", u"c", u"d", u"e",
            u"f", u"g", u"h", u'ij', u"k",
            u"l", u"m", u"n", u"o", u"p",
            u"q", u"r", u"s", u"t", u"u",
            u"v", u"w", u"x", u"y", u"z"
        ]
        return self.__encDec(alphabet, text, key, False)
