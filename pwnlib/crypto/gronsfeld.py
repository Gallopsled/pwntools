# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/gronsfeld.py

class cipher_gronsfeld:
    def process(self, alphabet, key, text, isEncrypt):
        ans = ""
        for i in range(len(text)):
            char = text[i]
            keyi = key[i % len(key)]
            try:
                alphIndex = (alphabet.index(char) + isEncrypt * keyi) % len(alphabet)
            except ValueError:
                wrchar = char.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            ans += alphabet[alphIndex]
        return ans


    def encrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text, 1)


    def decrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text, -1)
