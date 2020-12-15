# based on: https://github.com/tigertv/secretpy/blob/master/secretpy/ciphers/caesar_progressive.py

from pwnlib.crypto.helpers.alphabets import *

class cipher_caesar_progressive:
    __alphabet = al.ENGLISH

    def process(self, alphabet, key, text, isEncrypt):
        alphabet = alphabet or self.__alphabet
        ans = ""
        for i, char in enumerate(text):
            try:
                alphIndex = alphabet.index(char)
            except ValueError as e:
                wrchar = char.encode('utf-8')
                e.args = (
                    "Can't find char '" + wrchar + "' of text in alphabet!",)
                raise
            alphIndex = (alphIndex + isEncrypt * (key + i)) % len(alphabet)
            ans += alphabet[alphIndex]
        return ans


    def encrypt(self, text, key, alphabet=None):
        return self.process(alphabet, key, text, 1)


    def decrypt(self, text, key, alphabet=None):
        return self.process(alphabet, key, text, -1)
