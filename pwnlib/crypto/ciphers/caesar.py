import string

class cipher_caesar:
    def __init__(self):
        self.alphabet = string.ascii_lowercase + string.ascii_uppercase


    def encrypt(self, data, key, mode):
        return self.process(data, key, mode)


    def decrypt(self, data, key, mode):
        return self.process(data, key, mode)


    def process(self, text, key, mode):
        result = ''

        for c in text:
            index = self.alphabet.find(c)
            if index == -1:
                result += c
            else:
                new_index = index + key if mode == 1 else index - key
                new_index %= len(self.alphabet)
                result += self.alphabet[new_index:new_index+1]

        return result
