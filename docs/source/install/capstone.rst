Capstone
-------------

Capstone is a disassembly library required for gathering ROP gadgets
and ROP chain generation.

It's a separate requirement from ``binutils`` because it's used by
Jon Salwan's ``ROPgadget`` tool which we use under the covers.

In particular, version ``2.1.2`` should be used.  Capstone can be downloaded here_, or installed with the steps below.

Ubuntu
^^^^^^^^^^^^^^^^

.. code-block:: bash

    $ wget -nc http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_amd64.deb
    $ sudo dpkg -i capstone-2.1.2_amd64.deb

Mac OS X
^^^^^^^^^^^^^^^^

.. code-block:: bash

    $ brew install capstone

.. _here:  http://www.capstone-engine.org/download.html
