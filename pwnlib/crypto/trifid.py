# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/trifid.py

class cipher_trifid:
    alphabet = [
        u"a", u"b", u"c",
        u"d", u"e", u"f",
        u"g", u"h", u"i",

        u"j", u"k", u"l",
        u"m", u"n", u"o",
        u"p", u"q", u"r",

        u"s", u"t", u"u",
        u"v", u"w", u"x",
        u"y", u"z", u".",
    ]

    def __code(self, text, alphabet):
        code = ""
        for char in text:
            for index in range(len(alphabet)):
                try:
                    alphabet[index].index(char)
                    break
                except ValueError:
                    pass
            square = int(index / 9)
            index = index % 9
            row = int(index / 3)
            col = index % 3
            code += str(square+1) + str(row+1) + str(col+1)
        return code

    def __decode(self, text, alphabet):
        code = ""
        for i in range(0, len(text), 3):
            square = int(text[i])-1
            row = int(text[i+1])-1
            col = int(text[i+2])-1
            index = square*9 + row*3 + col
            code += alphabet[index][0]
        return code

    def __enc(self, alphabet, text, key):
        code = self.__code(text, alphabet)

        code0 = ""
        for j in range(0, len(text)*3, 3*key):
            for i in range(3):
                code0 += code[j+i:j+3*key:3]

        code = self.__decode(code0, alphabet)
        return code

    def __dec(self, alphabet, text, key):
        code = self.__code(text, alphabet)

        code0 = ""
        rmd = (len(text) % key)
        for j in range(0, (len(text) - rmd) * 3, 3*key):
            for i in range(key):
                code0 += code[j+i:j+3*key:key]

        j = (len(text) - rmd) * 3
        for i in range(rmd):
            code0 += code[j+i:j+3*rmd:rmd]

        code = self.__decode(code0, alphabet)
        return code

    def encrypt(self, text, key=None, alphabet=None):
        alphabet = alphabet or self.alphabet
        key = int(key)
        if not key > 0:
            key = len(text)
        return self.__enc(alphabet, text, key)


    def decrypt(self, text, key=None, alphabet=None):
        alphabet = alphabet or self.alphabet
        key = int(key)
        if not key > 0:
            key = len(text)
        return self.__dec(alphabet, text, key)
