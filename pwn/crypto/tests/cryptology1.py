# Solutions to cryptoanalysis exercises from
# Cryptology 1, 01410, Spring 2013 DTU
# Martin Bjerregaard Jepsen

import string

from pwn.crypto import *
import pwn.crypto.monoalphabetic as mono
import pwn.crypto.polyalphabetic as poly

print """
#############
# Chapter 2 #
#############"""

print """
2.6.1 Find 34^4 + 19^9 mod 16
"""

print "Solution: %d" % (util.fast_exponentiation(34, 4, 16) + util.fast_exponentiation(17,9, 16))

print """
2.6.2 Find (701 + 55)^98235411111 mod 7
"""

# Yes, this is stupid because 701 + 55 = 0 mod 7. But it
# is an example of the power of pwn.crypto
print "Solution: %d" % util.fast_exponentiation(701 + 55, 98235411111, 7)

print """
2.7 Find the multiplicative inverse of 8 modulo 71.
"""

print "Solution: %d" % util.modinv(8, 71)

print """
#############
# Chapter 3 #
#############"""

print """
3.1 Encrypt the message \"peanut\" using the Shift cipher with key k = 5
"""

print "Solution: '%s'" % mono.encrypt_shift("peanut", 5, string.lowercase)

print """
3.2 Decrypt the ciphertext \"PIZUU\" which was encrypted using the Affine
cipher with key k = (3, 13)
"""

print "Solution: '%s'" % mono.decrypt_affine("PIZUU", (3, 13))

print """
3.3 Consider the ciphertext \"JZMISBPQA\" encrypted using the Shift cipher.
Find the English plaintext and the key.
"""

(key, plaintext) = mono.crack_shift("JZMISBPQA")
print "Solution: '%s' using key k = %d" % (plaintext, key)

print """
3.4 Assume we have intercepted the following plaintext and ciphertext pairs
and assume that the Affine cipher has been used. Find the key.
    1. (m1, c1) = (2, 12) and (m2, c2) = (5, 3)
    2. (m1, c1) = (1, 7) and (m2, c2) = (4, 8)
"""

print "#TODO# Create known plaintext affine cracker"

print """
3.5 Consider the ciphertext \"FDWAVWEJFWXFOUDWJW\" encrypted using the Affine
cipher. Find the English plaintext and the key.
"""

print "Solution: '%s' using the key (, ) #TODO# Return better values" % mono.crack_affine("FDWAVWEJFWXFOUDWJW")[1]

print """
3.6 [...] Consider the following Vigenere ciphertext: \"EHVXZXAMXPVVZVVJEHVVZGZFEHVZZUJWEHVFEHVQOIJSAPVSCEU\".
    1. Try to determine the period of the key from repeating (likely) patterns.
    2. Try to determine the plaintext.
"""

ciphertext = "EHVXZXAMXPVVZVVJEHVVZGZFEHVZZUJWEHVFEHVQOIJSAPVSCEU"
print "Solution: '%s' using the key k = '%s' #TODO# Better vigenere cracking"
