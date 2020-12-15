class cipher_reverse:
    def encrypt(self, cleartext):
        return self.process(cleartext)


    def decrypt(self, ciphertext):
        return self.process(ciphertext)


    def process(self, text):
        return reversed(text)
