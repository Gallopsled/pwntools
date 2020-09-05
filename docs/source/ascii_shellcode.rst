.. testsetup:: *

   import struct
   import six
   from itertools import chain
   from itertools import product
   from pwnlib.util.iters import group
   from pwnlib.context import LocalContext
   from pwnlib.context import context
   from pwnlib.ascii_shellcode import asciify_shellcode, _get_allocator, _find_negatives, _get_subtractions, _calc_subtractions
   if six.PY2:
      import binascii
      hex2bytes = binascii.unhexlify
      bytes2hex = binascii.hexlify
   elif six.PY3:
      hex2bytes = bytes.fromhex
      bytes2hex = bytes.hex

:mod:`pwnlib.ascii_shellcode` --- ASCII Shell Code
==================================================

.. automodule:: pwnlib.ascii_shellcode
   :members:

Internal Functions
-----------------------------------------

These are only included so that their tests are run.

You should never need these.

.. autofunction:: pwnlib.ascii_shellcode._get_allocator
.. autofunction:: pwnlib.ascii_shellcode._find_negatives
.. autofunction:: pwnlib.ascii_shellcode._get_subtractions
.. autofunction:: pwnlib.ascii_shellcode._calc_subtractions