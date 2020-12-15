# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/affine.py

class cipher_affine:
    def process(self, alphabet, key, text, isEncrypt):
        a = key[0]
        b = key[1]
        ans = ""
        aInverse = self.__getInverse(a, alphabet)

        try:
            for char in text:
                if isEncrypt == 1:
                    alphI = (alphabet.index(char) * a + b) % len(alphabet)
                else:
                    alphI = (aInverse * (alphabet.index(char) - b)) % len(alphabet)
                enc = alphabet[alphI]
                ans += enc

        except ValueError:
            wrchar = char.encode('utf-8')
            raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")

        return ans


    def __getInverse(self, a, alphabet):
        for i in range(1, len(alphabet)):
            if ((int(a)*int(i)) % int(len(alphabet))) == 1:
                return i
        return 0


    def encrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text, 1)


    def decrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text, -1)
