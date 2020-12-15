# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/chao.py

class cipher_chao:

    def process(self, text, isEncrypt, tp_alphabet, tc_alphabet):
        ret = ''
        for c in text:
            try:
                if isEncrypt:
                    i = tp_alphabet.index(c)
                    ret += tc_alphabet[i]
                else:
                    i = tc_alphabet.index(c)
                    ret += tp_alphabet[i]
            except ValueError:
                wrchar = c.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            tc_alphabet = self.permuteAlphabet(tc_alphabet, i, True)
            tp_alphabet = self.permuteAlphabet(tp_alphabet, i, False)
        return ret


    def encrypt(self, text, key, alphabet=None):
        return self.process(text, True, alphabet, key)


    def decrypt(self, text, key, alphabet=None):
        return self.process(text, False, alphabet, key)


    def permuteAlphabet(self, alphabet, i, isCrypt):
        alphabet = alphabet[i:] + alphabet[:i]
        nadir = len(alphabet) / 2
        if isCrypt:
            alphabet = alphabet[0] + alphabet[2:int(nadir)+1] + alphabet[1] + alphabet[int(nadir)+1:]
        else:
            alphabet = alphabet[1:] + alphabet[0]
            alphabet = alphabet[:2] + alphabet[3:int(nadir)+1] + alphabet[2] + alphabet[int(nadir)+1:]
        return alphabet
