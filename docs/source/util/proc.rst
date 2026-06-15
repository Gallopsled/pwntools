.. testsetup:: *

   from pwnlib.util.proc import *
   from pwnlib.tubes.process import process
   import os, sys

   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']


:mod:`pwnlib.util.proc` --- Working with ``/proc/``
===================================================

.. automodule:: pwnlib.util.proc
   :members:
