from __future__ import absolute_import

# load cipher suites
from pwnlib.crypto.ciphers.atbash import CipherAtBash
from pwnlib.crypto.ciphers.bacon import CipherBacon
from pwnlib.crypto.ciphers.base64 import CipherBase64
from pwnlib.crypto.ciphers.binary import CipherBinary
from pwnlib.crypto.ciphers.caesar import CipherCaesar
from pwnlib.crypto.ciphers.decimal import CipherDecimal
from pwnlib.crypto.ciphers.hex import CipherHex
from pwnlib.crypto.ciphers.morse import CipherMorse
from pwnlib.crypto.ciphers.reverse import CipherReverse
from pwnlib.crypto.ciphers.rot13 import CipherRot13
from pwnlib.crypto.ciphers.transposition import CipherTransposition
from pwnlib.crypto.ciphers.vigenere import CipherVigenere
from pwnlib.crypto.ciphers.xor import CipherXor

class Crypto():
    def __init__(self, algo=None, key=None):
        cipher = None
        algo = algo
        key = key

        # select cipher suite
        if(algo == 'atbash'):
            self.cipher = CipherAtBash()
        if(algo == 'bacon'):
            self.cipher = CipherBacon()
        if(algo == 'base64'):
            self.cipher = CipherBase64()
        if(algo == 'binary'):
            self.cipher = CipherBinary()
        ''' check key, mode parameter
        if(algo == 'caesar'):
            self.cipher = CipherCaesar()
        if(algo == 'decimal'):
            self.cipher = CipherDecimal()
        '''
        if(algo == 'hex'):
            self.cipher = CipherHex()
        if(algo == 'morse'):
            self.cipher = CipherMorse()
        if(algo == 'reverse'):
            self.cipher = CipherReverse()
        if(algo == 'rot13'):
            self.cipher = CipherRot13()
        '''
        if(algo == 'transposition'):
            self.cipher = CipherTransposition()
        '''
        if(algo == 'vignere'):
            self.cipher = CipherVignere()
        if(algo == 'xor'):
            self.cipher = CipherXor()


    def encrypt(self, data):
        return self.cipher.encrypt(data)


    def decrypt(self, data):
        return self.cipher.decrypt(data)
