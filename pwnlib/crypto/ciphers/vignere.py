import string

class CipherVigenere:
    def __init__(self):
        self.alphabet = string.ascii_lowercase


    def new_alph(self, char):
        char = char.lower()
        new_alph = self.alphabet[self.alphabet.index(char):] + self.alphabet[:self.alphabet.index(char)]
        return new_alph


    def encrypt(self, cleartext, key):
        if(key == None):
            raise ValueError('No key given')

        if not (type(key) is str):
            if(type(key) is int):
                raise ValueError('Key must be string not int')
            else:
                raise ValueError('Key needs to be string')

        if(len(key) < len(cleartext)):
            raise ValueError('Key shorter then cleartext - loosing data')

        ciphertext = ''

        i = 1
        for char in key:
            new = self.new_alph(char)
            for t in cleartext:
                if self.alphabet.count(t) == 1 :
                    ciphertext += new[self.alphabet.index(t)]
                    cleartext = cleartext[i:]
                    break
                elif self.alphabet.count(t.lower()) == 1:
                    ciphertext += new[self.alphabet.index(t.lower())].upper()
                    cleartext = cleartext[i:]
                    break
                else:
                    ciphertext += t
                    cleartext = cleartext[i:]
                    break
                i += 1
        return ciphertext


    def decrypt(self, ciphertext, key):
        if(key is None):
            raise ValueError('No key given')

        if not (type(key) is str):
            if(type(key) is int):
                raise ValueError('Key must be string not int')
            else:
                raise ValueError('Key needs to be string')

        if(len(key) < len(ciphertext)):
            raise ValueError('Key shorter then cleartext - loosing data')

        cleartext = ''
        i = 1
        for char in key:
            new = self.new_alph(char)
            for t in ciphertext:
                if self.alphabet.count(t) == 1 :
                    cleartext += self.alphabet[new.index(t)]
                    ciphertext = ciphertext[i:]
                    break
                elif self.alphabet.count(t.lower()) == 1:
                    cleartext += self.alphabet[new.index(t.lower())].upper()
                    ciphertext = ciphertext[i:]
                    break
                else:
                    cleartext += t
                    ciphertext = ciphertext[i:]
                    break
                i += 1
        return cleartext
