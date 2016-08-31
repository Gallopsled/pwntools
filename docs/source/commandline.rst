.. testsetup:: *

   from pwn import *
   old = context.defaults.copy()

.. testcleanup:: *

    context.defaults.copy = old

Command Line Tools
========================

pwntools comes with a handful of useful command-line utilities which serve as wrappers for some of the internal functionality.

.. toctree::

.. autoprogram:: pwnlib.commandline.main:parser
   :prog: pwn
