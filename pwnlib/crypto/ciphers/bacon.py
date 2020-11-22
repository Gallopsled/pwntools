import re

class CipherBacon:
    def __init__(self):
        code_table = self.code_table()

    def code_table(self):
        bacon_dict = {}

        for i in range(0, 26):
            tmp = bin(i)[2:].zfill(5)
            tmp = tmp.replace('0', 'a')
            tmp = tmp.replace('1', 'b')
            bacon_dict[tmp] = chr(65 + i)

        return bacon_dict


    def encrypt(self, cleartext):
        cipher = ''
        bacon_dict = {v: k for k, v in self.code_table.items()}  # hack to get key from value - reverse dict
        #cleartext = normalize('NFKD', cleartext).encode('ascii', 'ignore')  # replace national characters to ASCII equivalents
        cleartext = cleartext.upper()
        cleartext = re.sub(r'[^A-Z]+', '', cleartext)

        for i in cleartext:
            cipher += bacon_dict.get(i).upper()
        return cipher


    def decrypt(self, ciphertext):
        cleartext = ''
        ciphertext = ciphertext.lower()
        ciphertext = re.sub(r'[^ab]+', '', ciphertext)

        for i in range(0, int(len(ciphertext) / 5)):
            cleartext += self.code_table.get(ciphertext[i * 5:i * 5 + 5], ' ')
        return cleartext
