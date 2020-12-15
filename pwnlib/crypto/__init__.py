from __future__ import absolute_import

# load cipher suites
from pwnlib.crypto.atbash import cipher_atbash
from pwnlib.crypto.bacon import cipher_bacon
from pwnlib.crypto.base64 import cipher_base64
from pwnlib.crypto.binary import cipher_binary
from pwnlib.crypto.caesar import cipher_caesar
from pwnlib.crypto.decimal import cipher_decimal
from pwnlib.crypto.hex import cipher_hex
from pwnlib.crypto.morse import cipher_morse
from pwnlib.crypto.reverse import cipher_reverse
from pwnlib.crypto.rot13 import cipher_rot13
from pwnlib.crypto.transposition import cipher_transposition
from pwnlib.crypto.vigenere import cipher_vigenere
from pwnlib.crypto.xor import cipher_xor

class crypto():
    def __init__(self, algo=None, key=None):
        cipher = None
        algo = algo
        key = key

        # select cipher suite
        if algo == 'atbash':
            self.cipher = cipher_atbash()
        if algo == 'bacon':
            self.cipher = cipher_bacon()
        if algo == 'base64':
            self.cipher = cipher_base64()
        if algo == 'binary':
            self.cipher = cipher_binary()
        ''' check key, mode parameter
        if algo == 'caesar':
            self.cipher = cipher_caesar()
        if algo == 'decimal':
            self.cipher = cipher_decimal()
        '''
        if algo == 'hex':
            self.cipher = cipher_hex()
        if algo == 'morse':
            self.cipher = cipher_morse()
        if algo == 'reverse':
            self.cipher = cipher_reverse()
        if algo == 'rot13':
            self.cipher = cipher_rot13()
        '''
        if algo == 'transposition':
            self.cipher = cipher_transposition()
        '''
        if algo == 'vigenere':
            self.cipher = cipher_vigenere()
        if algo == 'xor':
            self.cipher = cipher_xor()


    def encrypt(self, data):
        return self.cipher.encrypt(data)


    def decrypt(self, data):
        return self.cipher.decrypt(data)
