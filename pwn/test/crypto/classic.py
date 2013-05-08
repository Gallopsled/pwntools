#!/usr/bin/env python
import pwn.crypto.monoalphabetic as mono
import pwn.crypto.polyalphabetic as poly

plaintext = "THESECONDBRIGADEWASPREPARINGTOMOVETOFRANCEINGREATSECRECYHEDECIDEDITWASUNSAFETOTAKEHERINTOBATTLESOWHILEPASSINGTHROUGHLONDONONTHEWAYTOFRANCEHEVISITEDLONDONZOOANDASKEDTHEMTOCAREFORTHECUBUNTILHISRETURNWHICHHEOPTIMISTICALLYANTICIPATEDWOULDBENOLONGERTHANTWOWEEKSOFCOURSETHEWARWASNOTTOENDSOQUICKLY"

print "=== MONOALPHABETIC CIPHERS ==="

print "--- AFFINE CIPHER ---"
ciphertext = mono.encrypt_affine(plaintext, (11, 13))
decrypted = mono.decrypt_affine(ciphertext, (11, 13))
(key, cracked) = mono.crack_affine(ciphertext)
print "Ciphertext: %s\nDecrypted: %s\n Cracked: %s" % (ciphertext, decrypted, cracked)

print "--- ATBASH CIPHER ---"
ciphertext = mono.encrypt_atbash(plaintext)
decrypted = mono.decrypt_atbash(ciphertext)
cracked = mono.crack_atbash(ciphertext)
print "Ciphertext: %s\nDecrypted: %s\n Cracked: %s" % (ciphertext, decrypted, cracked)

print "--- SHIFT CIPHER ---"
ciphertext = mono.encrypt_shift(plaintext, 15)
decrypted = mono.decrypt_shift(ciphertext, 15)
(key, cracked) = mono.crack_shift(ciphertext)
print "Ciphertext: %s\nDecrypted: %s\n Cracked: %s" % (ciphertext, decrypted, cracked)

print "--- SUBSTITUTION CIPHER ---"
ciphertext = mono.encrypt_substitution(plaintext, mono._shift_dict(7))
decrypted = mono.decrypt_substitution(ciphertext, mono._shift_dict(7))
(key, cracked) = mono.crack_substitution(ciphertext, show_status=False)
print "Ciphertext: %s\nDecrypted: %s\n Cracked: %s" % (ciphertext, decrypted, cracked)

print "=== POLYALPHABETIC CIPHERS ==="

print "--- VIGENERE CIPHER ---"
ciphertext = poly.encrypt(plaintext, "EINNIW", poly.vigenere_cipher)
decrypted = poly.decrypt(ciphertext, "EINNIW", poly.vigenere_cipher)
(key, cracked) = poly.crack_vigenere(ciphertext)[0]
print "Ciphertext: %s\nDecrypted: %s\n Cracked: %s" % (ciphertext, decrypted, cracked)
