.. testsetup:: *

   from pwn import *
   old = context.defaults.copy()

.. testcleanup:: *

    context.defaults.copy = old

Command Line Tools
========================

pwntools comes with a handful of useful command-line utilities which serve as wrappers for some of the internal functionality.

If these tools do not appear to be installed, make sure that you have added ``~/.local/bin`` to your ``$PATH`` environment variable.

.. toctree::

.. autoprogram:: pwnlib.commandline.main:parser
   :prog: pwn
