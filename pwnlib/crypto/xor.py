class cipher_xor:
    @staticmethod
    def encrypt(a, b, byte=True):
        return cipher_xor.process(a, b, byte)


    @staticmethod
    def decrypt(a, b, byte=True):
        return cipher_xor.process(a, b, byte)


    @staticmethod
    def process(a, b, byte):
        if isinstance(a,str) is not isinstance(b, str):
            raise ValueError('Not same format exception')
    
        if isinstance(a,str) and isinstance(b, str):
            return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(a,b))
            
        if isinstance(a,bytes) and isinstance(b,bytes):
            return bytes([_a ^ _b for _a, _b in zip(a, b)])