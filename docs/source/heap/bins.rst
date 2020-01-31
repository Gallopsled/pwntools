.. testsetup:: *

   from pwnlib.heap.bins import *

:mod:`pwnlib.heap.bins` --- Bins of the libc
=============================================

Bins (abstract classes)
------------------------
Classes with generic behaviour that are inherit by the all
the bins types.

.. autoclass:: pwnlib.heap.bins.bin.Bins()
   :members:

.. autoclass:: pwnlib.heap.bins.bin.Bin()
   :members:

.. autoclass:: pwnlib.heap.bins.bin.BinEntry()
   :members:

Tcaches
--------
Classes to represent the tcache bins of the libc. Tcaches were
incorporated in libc 2.26, therefore this classes are only
used if the current libc version of the process is at least 2.26.

.. autoclass:: pwnlib.heap.bins.Tcaches()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.Tcache()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.TcacheEntry()
   :members:
   :show-inheritance:


Fast bins
----------
Classes to represent the tcache bins of the libc.

.. autoclass:: pwnlib.heap.bins.FastBins()
   :members:
   :show-inheritance:


.. autoclass:: pwnlib.heap.bins.FastBin()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.FastBinEntry()
   :members:
   :show-inheritance:

Unsorted bin
--------------
Classes to represent the unsorted bin of the libc.

.. autoclass:: pwnlib.heap.bins.UnsortedBins()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.UnsortedBin()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.UnsortedBinEntry()
   :members:
   :show-inheritance:

Small bins
------------
Classes to represent the small bins of the libc.

.. autoclass:: pwnlib.heap.bins.SmallBins()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.SmallBin()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.SmallBinEntry()
   :members:
   :show-inheritance:

Large bins
------------
Classes to represent the large bins of the libc.

.. autoclass:: pwnlib.heap.bins.LargeBins()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.LargeBin()
   :members:
   :show-inheritance:

.. autoclass:: pwnlib.heap.bins.LargeBinEntry()
   :members:
   :show-inheritance:
