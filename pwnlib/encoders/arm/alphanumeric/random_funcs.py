from __future__ import division

import os
import random
import struct


# +------------------------------------------------------------------------+
# |                       RANDOM NUMBERS FUNCTIONS                         |
# +------------------------------------------------------------------------+

# get a random integer i (0<=i<maxv)
# ==================================
def random_get_int(maxv):
   return random.randrange(0, maxv)


def randel(arr):
   return arr[random_get_int(len(arr))]

def enc_data_msn(c, i):
   # c is the lsn to be encoded with a msn
   # lsn = least significant nibble  msn = most significant nibble
   if c <= i:
      if c == 0:
         #Randomly select and return from {5,7}
         return randel([5, 7])
      else:
         #Randomly select and return from {4,5,6,7}
         return randel([4,5,6,7])
   elif c == 0:
      #Randomly select and return from {3,5,7}
      return randel([3,5,7])
   elif c <= 0x0A:
      #Randomly select and return from {3,4,5,6,7}
      #CSE Why doesn't the author use 3 below then?
      return randel([4,5,6,7])
   else:
      return randel([4,6])
