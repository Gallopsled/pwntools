.. testsetup:: *

   from glob import glob
   from pwn import *

   # The Linux kernel won't overwrite an existing corefile, so in case 
   # some other part of the doctests caused a segfault and core dump,
   # we need to get rid of it before our tests run.
   #
   # We DONT need to worry about e.g. ./core existing when using Corefile()
   # because we always move and rename the corefile to prevent this situation.
   if os.path.exists('core'): 
      os.unlink('core')

   # bash-static is a statically linked version of bash, but if $SHELL is not
   # set to anything, it decides to up and load ld.so and libc.so which breaks
   # our example of showing `corefile.libc == None` for a statically linked bin.
   # Set the environment here so it's not in the middle of our tests.
   os.environ.setdefault('SHELL', '/bin/sh')


:mod:`pwnlib.elf.corefile` --- Core Files
===========================================================

.. automodule:: pwnlib.elf.corefile

  .. autoclass:: pwnlib.elf.corefile.Corefile
     :members:
     :show-inheritance:

  .. autoclass:: pwnlib.elf.corefile.Mapping
     :members:
