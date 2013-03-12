import string
from random import randint

from pwn.crypto import *

def testResult(ciphername, plaintext, ciphertext, cracked):
    print "----- Testing %s cipher -----" % ciphername
    print "Original  : " + (plaintext if len(plaintext) < 100 else plaintext[:100] + "...")
    print "Encrypted : " + (ciphertext if len(ciphertext) < 100 else ciphertext + "...")
    print "Cracked   : " + (cracked if len(cracked) < 100 else cracked[:100] + "...")
    print "Passed." if (plaintext == cracked) else "Test failed!"

plaintext = "THEWEATHERISCHANGINGINTHEWORLDTODAYWESHOULDDOSOMETHINGFAST"
ciphertext = monoalphabetic.encrypt(plaintext, monoalphabetic.shiftDict(randint(1,25)))
(shift, cracked) = monoalphabetic.crackShift(ciphertext)
testResult("Shift", plaintext, ciphertext, cracked)

plaintext = "THEWEATHERISCHANGINGINTHEWORLDTODAYWESHOULDDOSOMETHINGFAST"
ciphertext = monoalphabetic.encrypt(plaintext, monoalphabetic.atbashDict())
cracked = monoalphabetic.decrypt(ciphertext, monoalphabetic.atbashDict())
testResult("Atbash", plaintext, ciphertext, cracked)

plaintext = "THEWEATHERISCHANGINGINTHEWORLDTODAYWESHOULDDOSOMETHINGFAST"
ciphertext = monoalphabetic.encrypt(plaintext, monoalphabetic.affineDict((11, randint(1,25))))
(shift, cracked) = monoalphabetic.crackAffine(ciphertext)
testResult("Affine", plaintext, ciphertext, cracked)

plaintext = "THESECONDBRIGADEWASPREPARINGTOMOVETOFRANCEINGREATSECRECYHEDECIDEDITWASUNSAFETOTAKEHERINTOBATTLESOWHILEPASSINGTHROUGHLONDONONTHEWAYTOFRANCEHEVISITEDLONDONZOOANDASKEDTHEMTOCAREFORTHECUBUNTILHISRETURNWHICHHEOPTIMISTICALLYANTICIPATEDWOULDBENOLONGERTHANTWOWEEKSOFCOURSETHEWARWASNOTTOENDSOQUICKLY"
ciphertext = polyalphabetic.encrypt(plaintext, "EINNIW", polyalphabetic.vigenere)
(_, cracked) = polyalphabetic.vigenereCrack(ciphertext)[0]
testResult("Vigenere", plaintext, ciphertext, cracked)
