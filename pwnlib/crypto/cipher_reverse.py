class cipher_reverse:
	def __init__(self):
		pass

	@staticmethod
	def process(cleartext):
		return reversed(cleartext)

	@staticmethod
	def encrypt(cleartext):
		return cipher_reverse.process(cleartext)
	
	@staticmethod
	def decrypt(ciphertext):
		return cipher_reverse.process(ciphertext)
	
