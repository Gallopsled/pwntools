Installation
============

binjitsu is best supported on Ubuntu 12.04 and 14.04, but most
functionality should work on any Posix-like distribution (Debian, Arch,
FreeBSD, OSX, etc.).

Prerequisites
-------------

In order to get the most out of ``binjitsu``, you should have the
following system libraries installed.

.. toctree::
   :maxdepth: 3
   :glob:

   install/*

Released Version
-----------------

binjitsu is available as a ``pip`` package.

.. code-block:: bash

    $ apt-get install python2.7 python2.7-dev python-pip
    $ pip install git+https://github.com/binjitsu/binjitsu.git

Latest Version
--------------

Alternatively if you prefer to use the latest version from the
repository:

.. code-block:: bash

    $ git clone https://github.com/binjitsu/binjitsu
    $ cd binjitsu
    $ pip install -e .

.. _Ubuntu: https://launchpad.net/~pwntools/+archive/ubuntu/binutils
