class cipher_morse:
    def __init__(self):
        self.code_table = self.generate_code_table()


    def generate_code_table(self):
        code_table = {
            'A':'.-', 'B':'-...',
            'C':'-.-.', 'D':'-..', 'E':'.',
            'F':'..-.', 'G':'--.', 'H':'....',
            'I':'..', 'J':'.---', 'K':'-.-',
            'L':'.-..', 'M':'--', 'N':'-.',
            'O':'---', 'P':'.--.', 'Q':'--.-',
            'R':'.-.', 'S':'...', 'T':'-',
            'U':'..-', 'V':'...-', 'W':'.--',
            'X':'-..-', 'Y':'-.--', 'Z':'--..',
            '1':'.----', '2':'..---', '3':'...--',
            '4':'....-', '5':'.....', '6':'-....',
            '7':'--...', '8':'---..', '9':'----.',
            '0':'-----', ', ':'--..--', '.':'.-.-.-',
            '?':'..--..', '/':'-..-.', '-':'-....-',
            '(':'-.--.', ')':'-.--.-'
        }

        return code_table


    def encrypt(self, cleartext):
        ciphertext = ''
        for char in cleartext:
            if char != ' ':
                ciphertext += self.code_table[char.upper()] + ' '
            else:
                ciphertext += ' '

        return ciphertext


    def decrypt(self, ciphertext):
        ciphertext += ' '
        cleartext = ''
        citext = ''
        for char in ciphertext:
            if (char != ' '):
                i = 0
                citext += char
            else:
                i += 1
                if i == 2 :
                    cleartext += ' '
                else:
                    cleartext += list(self.code_table.keys())[list(self.code_table.values()).index(citext)]
                    citext = ''

        return cleartext
