.. testsetup:: *

   from pwn import *
   import logging
   log = pwnlib.log.getLogger('pwnlib.context')
   context.clear()

:mod:`pwnlib.context` --- Setting runtime variables
=====================================================

Many settings in ``pwntools`` are controlled via the global variable :data:`.context`, such as the selected target operating system, architecture, and bit-width.

In general, exploits will start with something like:

.. code-block:: python

    from pwn import *
    context.arch = 'amd64'

Which sets up everything in the exploit for exploiting a 64-bit Intel binary.

The recommended method is to use ``context.binary``  to automagically set all of the appropriate values.

.. code-block:: python

    from pwn import *
    context.binary = './challenge-binary'

Module Members
----------------------------------------------------

.. automodule:: pwnlib.context
   :members:
