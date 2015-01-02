Installation
============

pwntools is best supported on Ubuntu 12.04 and 14.04, but most
functionality should work on any Posix-like distribution (Debian, Arch,
FreeBSD, OSX, etc.).

Prerequisites
-------------

In order to get the most out of ``pwntools``, you should have the
following system libraries installed.

.. toctree::
   :maxdepth: 3
   :glob:

   install/*

Released Version
-----------------

Pwntools is available as a ``pip`` package.

.. code-block:: bash

    $ apt-get install python2.7 python2.7-dev python-pip
    $ pip install pwntools

Latest Version
--------------

Alternatively if you prefer to use the latest version from the
repository:

.. code-block:: bash

    $ git clone https://github.com/Gallopsled/pwntools
    $ cd pwntools
    $ pip install -e .

.. _Ubuntu: https://launchpad.net/~pwntools/+archive/ubuntu/binutils
.. _libcapstone 2.1: http://www.capstone-engine.org
.. _i386: http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_i386.deb
.. _amd64: http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_amd64.deb

