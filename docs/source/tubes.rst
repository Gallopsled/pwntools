.. testsetup:: *

   from pwn import *

   # redirect logging to `sys.stdout`
   import logging
   logging.getLogger('pwnlib').handlers[0].stream = sys.stdout

:mod:`pwnlib.tubes` --- Talking to the World!
=============================================

.. automodule:: pwnlib.tubes


Types of Tubes
-------------------

.. toctree::
    :maxdepth: 3
    :glob:

    tubes/*


:mod:`pwnlib.tubes.tube` --- Common Functionality
-------------------------------------------------


.. automodule:: pwnlib.tubes.tube

  .. autoclass:: pwnlib.tubes.tube.tube()
     :members:
     :exclude-members: recv_raw, send_raw, settimeout_raw,
                       can_recv_raw
