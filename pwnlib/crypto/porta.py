class cipher_porta:
    def __init__(self):
        self.alphabet = list(string.ascii_uppercase)


    def process(self, alphabet, key, text):
        ans = ""
        for i, char in enumerate(text):
            try:
                keychari = alphabet.index(key[i % len(key)]) >> 1
            except ValueError:
                wrchar = key[i % len(key)].encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            try:
                textindex = alphabet.index(char)
            except ValueError:
                wrchar = char.encode('utf-8')
                raise Exception("Can't find char '" + wrchar + "' of text in alphabet!")
            half = len(alphabet) >> 1
            half_alphabet = None
            if textindex < half:
                half_alphabet = alphabet[half:]
                alphIndex = (textindex + keychari) % half
            else:
                half_alphabet = alphabet[0:half]
                alphIndex = (textindex - keychari) % half
            ans += half_alphabet[alphIndex]
        return ans


    def encrypt(self, text, key, alphabet=alphabets.ENGLISH):
        return self.__encDec(alphabet, key, text)


    def decrypt(self, text, key, alphabet=alphabets.ENGLISH):
        return self.__encDec(alphabet, key, text)
