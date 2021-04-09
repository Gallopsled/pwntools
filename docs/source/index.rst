pwntools
====================================

``pwntools`` is a CTF framework and exploit development library.
Written in Python, it is designed for rapid prototyping and development,
and intended to make exploit writing as simple as possible.

The primary location for this documentation is at docs.pwntools.com_, which uses
readthedocs_. It comes in three primary flavors:

- Stable_
- Beta_
- Dev_

.. _readthedocs: https://readthedocs.org
.. _docs.pwntools.com: https://docs.pwntools.com
.. _Stable: https://docs.pwntools.com/en/stable
.. _Beta: https://docs.pwntools.com/en/beta
.. _Dev: https://docs.pwntools.com/en/dev


Getting Started
---------------

.. toctree::
   :maxdepth: 3
   :glob:

   about
   install
   intro
   globals
   commandline


Module Index
------------

Each of the ``pwntools`` modules is documented here.

.. toctree::
   :maxdepth: 1
   :glob:

   adb
   args
   asm
   atexception
   atexit
   constants
   config
   context
   dynelf
   encoders
   elf
   exception
   filepointer
   filesystem
   flag
   fmtstr
   gdb
   libcdb
   log
   memleak
   protocols
   qemu
   replacements
   rop
   rop/*
   runner
   shellcraft
   shellcraft/*
   term
   timeout
   tubes
   tubes/*
   ui
   update
   useragents
   util/*

.. toctree::
   :hidden:

   testexample

.. only:: not dash

   Indices and tables
   ==================

   * :ref:`genindex`
   * :ref:`modindex`
   * :ref:`search`
