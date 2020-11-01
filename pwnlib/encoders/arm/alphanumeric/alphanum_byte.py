from __future__ import division
from __future__ import absolute_import

from . import random_funcs

# +------------------------------------------------------------------------+ 
# |                    ALPHANUMERIC MANIPULATIONS FUNCTIONS                | 
# +------------------------------------------------------------------------+ 

ALPHANUMERIC_BYTES = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# return 1 if the byte is alphanumeric 
# ==================================== 
def alphanumeric_check(c):
   if type(c) == int:
      c = chr(c & 0xff)
   return c.isalnum()


# return a random alphanumeric byte 
# ================================= 
def alphanumeric_get_byte():
   return ord(random_funcs.randel(ALPHANUMERIC_BYTES))

# return a randomly selected alphanumeric byte less than max 
# ========================================================== 
#CSE author actually returns a byte <= max, not strictly < max
def alphanumeric_get_byte_ltmax(max):
   sz = 0
   while sz < len(ALPHANUMERIC_BYTES) and ord(ALPHANUMERIC_BYTES[sz]) <= max:
      sz += 1
   return ord(random_funcs.randel(ALPHANUMERIC_BYTES[:sz]))

# generate an alphanumeric offset such that c+offset is also alphanumeric 
# ======================================================================= 
def off_gen(c):
   if c >= 0 and c <= 0x4a:
      max = 16 * 7 + 10 - c
      while True:
         x = alphanumeric_get_byte_ltmax(max)
         if alphanumeric_check(c + x):
            return x
   return 0

# return an alphanumeric value ret such that c XOR ret is also alphanumeric
# =========================================================================
def alphanumeric_get_complement(c):
   c &= 0xff
   while True:
      ret = alphanumeric_get_byte()
      if alphanumeric_check(c ^ ret):
         return ret
