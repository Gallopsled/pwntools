About pwntools
========================

Whether you're using it to write exploits, or as part
of another software project will dictate how you use it.

Historically pwntools was used as a sort of exploit-writing DSL. Simply doing
``from pwn import *`` in a previous version of pwntools would bring all sorts of
nice side-effects.

When redesigning pwntools for 2.0, we noticed two contrary goals:

* We would like to have a "normal" python module structure, to allow other
  people to familiarize themselves with pwntools quickly.
* We would like to have even more side-effects, especially by putting the
  terminal in raw-mode.

To make this possible, we decided to have two different modules. :mod:`pwnlib`
would be our nice, clean Python module, while :mod:`pwn` would be used during
CTFs.

:mod:`pwn` --- Toolbox optimized for CTFs
-----------------------------------------

.. module:: pwn

As stated, we would also like to have the ability to get a lot of these
side-effects by default. That is the purpose of this module. It does
the following:

* Imports everything from the toplevel :mod:`pwnlib` along with
  functions from a lot of submodules. This means that if you do
  ``import pwn`` or ``from pwn import *``, you will have access to
  everything you need to write an exploit.
* Calls :func:`pwnlib.term.init` to put your terminal in raw mode
  and implements functionality to make it appear like it isn't.
* Setting the :data:`pwnlib.context.log_level` to `"info"`.
* Tries to parse some of the values in :data:`sys.argv` and every
  value it succeeds in parsing it removes.

:mod:`pwnlib` --- Normal python library
---------------------------------------

.. module:: pwnlib

This module is our "clean" python-code. As a rule, we do not think that
importing :mod:`pwnlib` or any of the submodules should have any significant
side-effects (besides e.g. caching).

For the most part, you will also only get the bits you import. You for instance would
not get access to :mod:`pwnlib.util.packing` simply by doing ``import
pwnlib.util``.

Though there are a few exceptions (such as :mod:`pwnlib.shellcraft`), that does
not quite fit the goals of being simple and clean, but they can still be
imported without implicit side-effects.
