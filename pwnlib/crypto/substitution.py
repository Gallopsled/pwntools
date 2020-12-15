# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/simplesubstitution.py

class cipher_substitution:
    def __encDec(self, alphabet, key, text, isEncrypt):
        if len(alphabet) != len(key):
            return

        ans = ""
        for i in range(len(text)):
            m = text[i]
            k = ""
            try:
                if isEncrypt == 1:
                    k = key[alphabet.index(m)]
                else:
                    k = alphabet[key.index(m)]
            except ValueError:
                wrchar = m.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            ans += k
        return ans


    def encrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.__encDec(alphabet, key, text, 1)


    def decrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.__encDec(alphabet, key, text, -1)
