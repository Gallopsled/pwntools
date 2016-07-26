.. testsetup:: *

   from pwn import *
   old = context.defaults.copy()

.. testcleanup:: *

    context.defaults.copy = old

Command Line Tools
========================

pwntools comes with a handful of useful command-line utilities which serve as wrappers for some of the internal functionality.

.. toctree::

.. autoprogram:: pwnlib.commandline.asm:parser
   :prog: asm

.. autoprogram:: pwnlib.commandline.checksec:parser
   :prog: checksec

.. autoprogram:: pwnlib.commandline.constgrep:p
   :prog: constgrep

.. autoprogram:: pwnlib.commandline.cyclic:parser
   :prog: cyclic

.. autoprogram:: pwnlib.commandline.disasm:parser
   :prog: disasm

.. autoprogram:: pwnlib.commandline.elfdiff:p
   :prog: elfdiff

.. autoprogram:: pwnlib.commandline.elfpatch:p
   :prog: elfpatch

.. autoprogram:: pwnlib.commandline.errno:parser
   :prog: errno

.. autoprogram:: pwnlib.commandline.hex:parser
   :prog: hex

.. autoprogram:: pwnlib.commandline.phd:parser
   :prog: phd

.. autoprogram:: pwnlib.commandline.pwnstrip:p
   :prog: pwnstrip

.. autoprogram:: pwnlib.commandline.scramble:parser
   :prog: scramble

.. autoprogram:: pwnlib.commandline.shellcraft:p
   :prog: shellcraft

.. autoprogram:: pwnlib.commandline.unhex:parser
   :prog: unhex

