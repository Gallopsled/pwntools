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

    $ apt-get update
    $ apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
    $ pip install --upgrade pip
    $ pip install --upgrade pwntools

Development
--------------

If you are hacking on Pwntools locally, you'll want to do something like this:

.. code-block:: bash

    $ git clone https://github.com/Gallopsled/pwntools
    $ pip install --upgrade --editable ./pwntools

.. _Ubuntu: https://launchpad.net/~pwntools/+archive/ubuntu/binutils
