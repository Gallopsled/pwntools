from __future__ import absolute_import

# load cipher suites
from pwnlib.crypto.ciphers.atbash import cipher_atbash
from pwnlib.crypto.ciphers.bacon import cipher_bacon
from pwnlib.crypto.ciphers.base64 import cipher_base64
from pwnlib.crypto.ciphers.binary import cipher_binary
from pwnlib.crypto.ciphers.caesar import cipher_caesar
from pwnlib.crypto.ciphers.decimal import cipher_decimal
from pwnlib.crypto.ciphers.hex import cipher_hex
from pwnlib.crypto.ciphers.morse import cipher_morse
from pwnlib.crypto.ciphers.reverse import cipher_reverse
from pwnlib.crypto.ciphers.rot13 import cipher_rot13
from pwnlib.crypto.ciphers.transposition import cipher_transposition
from pwnlib.crypto.ciphers.vigenere import cipher_vigenere
from pwnlib.crypto.ciphers.xor import cipher_xor

class Crypto():
    def __init__(self, algo=None, key=None):
        cipher = None
        algo = algo
        key = key

        # select cipher suite
        if(algo == 'atbash'):
            self.cipher = cipher_atbash()
        if(algo == 'bacon'):
            self.cipher = cipher_bacon()
        if(algo == 'base64'):
            self.cipher = cipher_base64()
        if(algo == 'binary'):
            self.cipher = cipher_binary()
        ''' check key, mode parameter
        if(algo == 'caesar'):
            self.cipher = CipherCaesar()
        if(algo == 'decimal'):
            self.cipher = CipherDecimal()
        '''
        if(algo == 'hex'):
            self.cipher = cipher_hex()
        if(algo == 'morse'):
            self.cipher = cipher_morse()
        if(algo == 'reverse'):
            self.cipher = cipher_reverse()
        if(algo == 'rot13'):
            self.cipher = cipher_rot13()
        '''
        if(algo == 'transposition'):
            self.cipher = CipherTransposition()
        '''
        if(algo == 'vignere'):
            self.cipher = cipher_vigenere()
        if(algo == 'xor'):
            self.cipher = cipher_xor()


    def encrypt(self, data):
        return self.cipher.encrypt(data)


    def decrypt(self, data):
        return self.cipher.decrypt(data)
