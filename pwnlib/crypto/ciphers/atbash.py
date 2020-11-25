import string

class cipher_atbash:
    def __init__(self):
        self.alphabet = list(string.ascii_uppercase)


    def encrypt(self, clear):
        return self.process(clear)


    def decrypt(self, cipher):
        return self.process(cipher)


    def process(self, text):
        reverse_alphabet = list(reversed(self.alphabet))
        code_dictionary = dict(zip(self.alphabet, reverse_alphabet))

        chars = list(text.upper())
        result = ""

        for char in chars:
            if char in code_dictionary:
                result += code_dictionary.get(char)
            else:
                result += char

        return result
