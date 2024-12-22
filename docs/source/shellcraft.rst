.. testsetup:: *

   from pwnlib import shellcraft

   # TODO: Remove global POSIX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']

:mod:`pwnlib.shellcraft` --- Shellcode generation
=================================================

.. automodule:: pwnlib.shellcraft

.. TODO:

   Write a guide to adding more shellcode.

Submodules
----------

.. toctree::
   :glob:

   shellcraft/*
