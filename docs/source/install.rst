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

pwntools is available as a ``pip`` package.

.. code-block:: bash

    $ apt-get install python2.7 python2.7-dev python-pip
    $ pip install --upgrade pwntools

Alternatively you can get early access to the beta release if you want to help
file bugs or simple get newer features:

.. code-block:: bash

    $ pip install --upgrade --pre pwntools


Development
--------------

If you are hacking on Pwntools locally, you'll want to do something like this:

.. code-block:: bash

    $ git clone https://github.com/Gallopsled/pwntools
    $ cd pwntools
    $ pip install -e .

.. _Ubuntu: https://launchpad.net/~pwntools/+archive/ubuntu/binutils
