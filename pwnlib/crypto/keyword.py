#based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/keyword.py

from collections import OrderedDict

class cipher_keyword:
    """
    The Keyword Cipher
    """

    def __removeDup(self, input_str):
        newstring = input_str[0]
        for i in range(len(input_str)):
            if newstring[(len(newstring) - 1)] != input_str[i]:
                newstring += input_str[i]
            else:
                pass
        return newstring

    def process(self, alphabet, key, text, isEncrypt):
        # remove repeats of letters in the key
        newkey = "".join(OrderedDict.fromkeys(key))
        # create the substitution string
        longkey = "".join(OrderedDict.fromkeys(newkey+"".join(alphabet)))
        # do encryption
        ans = ""
        for i in range(len(text)):
            m = text[i]
            try:
                if isEncrypt == 1:
                    index = alphabet.index(m)
                    enc = longkey[index]
                else:
                    index = longkey.index(m)
                    enc = alphabet[index]
            except ValueError:
                wrchar = m.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            ans += enc
        return ans


    def encrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text, 1)


    def decrypt(self, text, key, alphabet=u"abcdefghijklmnopqrstuvwxyz"):
        return self.process(alphabet, key, text, -1)
