# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/autokey.py

class cipher_autokey:
    def process(self, alphabet, key, text, isEncrypt):
        ans = ""
        for i in range(len(text)):
            m = text[i]
            if i < len(key):
                k = key[i]
            else:
                if isEncrypt == 1:
                    k = text[i - len(key)]
                else:
                    k = ans[i - len(key)]
            try:
                alphI = alphabet.index(m)
            except ValueError:
                wrchar = m.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            try:
                alphI += isEncrypt * alphabet.index(k)
            except ValueError:
                wrchar = k.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            alphI = alphI % len(alphabet)
            enc = alphabet[alphI]
            ans += enc
        return ans


    def encrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text, 1)

    def decrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text, -1)
