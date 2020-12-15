# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/beaufort.py

class cipher_beaufort:
    def process(self, alphabet, key, text):
        ans = ""
        for i in range(len(text)):
            char = text[i]
            keychar = key[i % len(key)]
            try:
                alphIndex = alphabet.index(keychar)
            except ValueError:
                wrchar = keychar.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            try:
                alphIndex -= alphabet.index(char)
            except ValueError:
                wrchar = char.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            alphIndex %= len(alphabet)
            ans += alphabet[alphIndex]
        return ans


    def encrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text)


    def decrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text)
