import binascii

class cipher_binary:
    def encrypt(self, data):
        return bin(int(binascii.hexlify(data.encode('utf-8')),16))


    def decrypt(self, data):
        n = int(data, 2)
        return binascii.unhexlify('%x' % n).decode()
