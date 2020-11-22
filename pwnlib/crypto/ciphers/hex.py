import binascii

class CipherHex:
    def encrypt(self, data):
        result = ''

        for char in data:
            result += binascii.hexlify(char.encode('utf-8')).decode()

        return result


    def decrypt(self, data):
        return binascii.unhexlify(data).decode()
