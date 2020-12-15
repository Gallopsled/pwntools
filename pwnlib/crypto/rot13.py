import codecs

class cipher_rot13:
    def encrypt(self, data):
        return codecs.encode(data, 'rot13')


    def decrypt(self, data):
        return codecs.decode(data, 'rot13')
