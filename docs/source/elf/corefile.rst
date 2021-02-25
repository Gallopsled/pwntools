.. testsetup:: *

   from glob import glob
   from pwn import *

   # The Linunx kernel won't overwrite an existing corefile, so in case 
   # some other part of the doctests caused a segfault and core dump,
   # we need to get rid of it before our tests run.
   #
   # We DONT need to worry about e.g. ./core existing when using Corefile()
   # because we always move and rename the corefile to prevent this situation.
   if os.path.exists('core'): 
      os.unlink('core')


:mod:`pwnlib.elf.corefile` --- Core Files
===========================================================

.. automodule:: pwnlib.elf.corefile

  .. autoclass:: pwnlib.elf.corefile.Corefile
     :members:
     :show-inheritance:

  .. autoclass:: pwnlib.elf.corefile.Mapping
     :members:
