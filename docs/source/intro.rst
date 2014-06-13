Introduction to pwntools
========================

Historically pwntools was used as a sort of exploit-writing DSL. Simply doing
``from pwn import *`` in a previous version of pwntools would bring all sorts of
nice side-effects.

When redesigning pwntools for 2.0, we noticed two contrary goals:

* We would like to have a "normal" python module structure, to allow other
  people to faster get familiar with how pwntools works.
* We would like to have even more side-effects, especially by putting the
  terminal in raw-mode.

To make this possible, we decided to have two different modules. :mod:`pwnlib`
would be our nice, clean python module, while :mod:`pwn` would be used during
CTFs.

:mod:`pwnlib`
----------

.. module:: pwnlib

This module is our "clean" python-code. As a rule, we do not think that
importing :mod:`pwnlib` or any of the submodules should have any significant
side-effects (besides e.g. caching).

For the most part, you will also only get the bits you import. You for instance
not get access to :mod:`pwnlib.util.packing` simply by doing ``import
pwnlib.util``.

Though there are a few exceptions (such as :mod:`pwnlib.shellcraft`), that does
not quite fit the goals of being simple and clean, but they can still be
imported without implicit side-effects.

:mod:`pwn`
----------

.. module:: pwn

As stated, we would also like to have the ability to get a lot of these
side-effects by default. That is the purpose of this module. If you do an ``from
pwn import *``, you will get all functionality of the :mod:``pwnlib`` imported
to your top-level scope, and also a few conveniences such as:

* Calling :func:`pwnlib.term.take_ownership` to put your terminal in raw mode
  and implementing functionality to make it look like it is not.
* Setting the :data:`pwnlib.context.log_level` to `"info"`.
* Parsing :data:`sys.argv`.

Lalal, pwntools is nice.
