import base64

class CipherBase64:
    def encrypt(self, cleartext):
        return base64.b64encode(cleartext.encode('utf-8')).decode()


    def decrypt(self, ciphertext):
        return base64.b64decode(ciphertext.encode('utf-8')).decode()
