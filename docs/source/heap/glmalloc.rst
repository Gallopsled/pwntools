.. testsetup:: *

   from pwnlib.heap.glmalloc import *
   from pwnlib.tubes.process import process


:mod:`pwnlib.heap.glmalloc` --- glibc malloc
===================================================

.. automodule:: pwnlib.heap.glmalloc
   :members:

Heap Items
-------------
.. toctree::
    :maxdepth: 3
    :glob:

    gmalloc/*

Heap Explorer
---------------
.. autoclass:: pwnlib.heap.glmalloc.HeapExplorer()
   :members:
