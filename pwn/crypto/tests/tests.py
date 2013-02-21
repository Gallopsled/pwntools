import string
from random import randint

import Utilities
import Frequencies
import MonoAlphabetic
import PolyAlphabetic

def testResult(ciphername, plaintext, ciphertext, cracked):
    print "----- Testing %s cipher -----" % ciphername
    print "Original  : " + (plaintext if len(plaintext) < 100 else plaintext[:100] + "...")
    print "Encrypted : " + (ciphertext if len(ciphertext) < 100 else ciphertext[:100] + "...")
    print "Cracked   : " + (cracked if len(cracked) < 100 else cracked[:100] + "...")
    print "Passed." if (plaintext == cracked) else "Test failed!"

plaintext = "THEWEATHERISCHANGINGINTHEWORLDTODAYWESHOULDDOSOMETHINGFAST"
ciphertext = MonoAlphabetic.encrypt(plaintext, MonoAlphabetic.shiftDict(randint(1,25)))
(shift, cracked) = MonoAlphabetic.crackShift(ciphertext)
testResult("Shift", plaintext, ciphertext, cracked)

plaintext = "THEWEATHERISCHANGINGINTHEWORLDTODAYWESHOULDDOSOMETHINGFAST"
ciphertext = MonoAlphabetic.encrypt(plaintext, MonoAlphabetic.atbashDict())
cracked = MonoAlphabetic.decrypt(ciphertext, MonoAlphabetic.atbashDict())
testResult("Atbash", plaintext, ciphertext, cracked)

plaintext = "THEWEATHERISCHANGINGINTHEWORLDTODAYWESHOULDDOSOMETHINGFAST"
ciphertext = MonoAlphabetic.encrypt(plaintext, MonoAlphabetic.affineDict((11, randint(1,25))))
(shift, cracked) = MonoAlphabetic.crackAffine(ciphertext)
testResult("Affine", plaintext, ciphertext, cracked)

plaintext = "THESECONDBRIGADEWASPREPARINGTOMOVETOFRANCEINGREATSECRECYHEDECIDEDITWASUNSAFETOTAKEHERINTOBATTLESOWHILEPASSINGTHROUGHLONDONONTHEWAYTOFRANCEHEVISITEDLONDONZOOANDASKEDTHEMTOCAREFORTHECUBUNTILHISRETURNWHICHHEOPTIMISTICALLYANTICIPATEDWOULDBENOLONGERTHANTWOWEEKSOFCOURSETHEWARWASNOTTOENDSOQUICKLY"
ciphertext = PolyAlphabetic.encrypt(plaintext, "EINNIW", PolyAlphabetic.vigenere)
(_, cracked) = PolyAlphabetic.vigenereCrack(ciphertext)[0]
testResult("Vigenere", plaintext, ciphertext, cracked)
