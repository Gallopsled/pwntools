import binascii

class CipherDecimal:
    def encrypt(self, data):
        result = ''

        for char in data:
            result += ord(char)

        return result


    def decrypt(self, data):
        result = ''

        for num in data:
            result += chr(num)

        return result
