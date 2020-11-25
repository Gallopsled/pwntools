class xor:
    def encrypt(self, string_a, string_b):
        return self.process(string_a, string_b)


    def decrypt(self, string_a, string_b):
        return self.process(string_a, string_b)


    def process(self, string_a, string_b):
        return ''.join([hex(ord(string_a[i%len(string_a)]) ^ ord(string_b[i%(len(string_b))]))[2:] for i in range(max(len(string_a), len(string_b)))])
