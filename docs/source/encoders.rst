.. testsetup:: *

   from pwn import *

   # TODO: Remove global POSIX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']
   
:mod:`pwnlib.encoders` --- Encoding Shellcode
===============================================

Encoder selection
-----------------

The public :func:`pwnlib.encoders.encode` function accepts byte values to
avoid and an optional higher-order ``constraint``.  Supported constraint names
are ``alphabetic``, ``alphanumeric``, ``ascii``, ``utf8mb3``, and ``utf8``.
The input is returned unchanged when it already satisfies the request unless
``force`` is set.

Each encoder publishes its supported architectures, priority, unavoidable
decoder bytes, supported constraints, and deterministic-output behavior.
Candidates are ordered by output quality, priority, module, and class name.
Only :class:`pwnlib.encoders.encoder.EncoderError` and legacy
``NotImplementedError`` rejections cause fallback; unexpected implementation
errors propagate to the caller.

The i386 ASCII encoder is opt-in and is selected by the ``ascii``, ``utf8mb3``,
or ``utf8`` constraints.  It remains excluded from unconstrained selection
because its decoder executes on the stack and requires a fixed instruction
alphabet.

.. automodule:: pwnlib.encoders.encoder
   :members:

.. automodule:: pwnlib.encoders.i386.ascii_shellcode
   :members:
   :special-members:
   :exclude-members: __init__

.. automodule:: pwnlib.encoders.i386.xor
   :members:

.. automodule:: pwnlib.encoders.i386.delta
   :members:

.. automodule:: pwnlib.encoders.amd64.delta
   :members:

.. automodule:: pwnlib.encoders.arm.xor
   :members:

.. automodule:: pwnlib.encoders.arm.alphanumeric
   :members:

.. automodule:: pwnlib.encoders.mips.xor
   :members:
