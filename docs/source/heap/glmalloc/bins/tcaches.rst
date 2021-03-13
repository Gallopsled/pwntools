Tcaches
========
Classes to represent the tcache bins of the libc. Tcaches were
incorporated in libc 2.26, therefore this classes are only
used if the current libc version of the process is at least 2.26.

Tcaches
--------
.. autoclass:: pwnlib.heap.glmalloc.Tcaches()
   :members:
   :show-inheritance:

Tcache
-------
.. autoclass:: pwnlib.heap.glmalloc.Tcache()
   :members:
   :show-inheritance:

TcacheEntry
------------
.. autoclass:: pwnlib.heap.glmalloc.TcacheEntry()
   :members:
   :show-inheritance: