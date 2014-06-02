.. testsetup:: *

   import pwn2.lib
   from pwn2.lib import context
   context.reset_local()


:mod:`pwn2.lib.context` --- Setting runtime variables
=====================================================

The purpose of this module is to store runtime configuration of pwntools, such
as the level of logging or the default architecture for shellcode.

It is implemented as a restricted dictionary, with a predefined number of
keys and with each key having restrictions of which values it will allow.

The values are available both in a thread-local version and as a global
default. You are able to read or write each version separately. If you try to
read from the thread-local version, and no value is found, then the global
default is checked.

The thread-local version is available in :mod:`pwn2.lib.context` and the global
defaults are available in :mod:`pwn2.lib.context.defaults`.

.. note::

   Ideally, we would want to clone the thread-local context on thread creation,
   but do not know of a way to hook thread creation.


:mod:`pwn2.lib.context`
-----------------------

.. automodule:: pwn2.lib.context

   The following variables are all thread-local variables. They can be read or
   written directly:

   .. doctest:: test_context_example

      >>> print context.arch
      None
      >>> context.arch = 'i386'
      >>> print context.arch
      i386
      >>> context.arch = 'mill'
      Traceback (most recent call last):
          ...
      AttributeError: Cannot set context-key arch to 'mill', it is not in the list of allowed values


   If read, their valued will be looked up in the thread-local dictionary and if
   found returned, otherwise it will default to the global default store. If it
   is not found in the global store either, ``None`` will be returned.

   If writen to, the value will be saved only in the thread-local storage.


   .. data:: arch

      Variable for the current architecture. This is useful e.g. to make
      :mod:`pwn2.lib.shellcraft` easier to use.

      Allowed values:

      * ``i386``
      * ``amd64``
      * ``arm``
      * ``armel``
      * ``armeb``
      * ``ppc``

   .. data:: net

      Variable for the current network-stack. This is not currently useful, as
      we only support IPv4, but we'll get there eventually...

      .. todo::

         Update documentation when this changes.

      Allowed values:

      * ``tcp4`` (TCP over IPv4)
      * ``tcp6`` (TCP over IPv6)

   .. data:: os

      Variable for the current operating system. This is useful e.g. for
      choosing the right constants for syscall numbers.

      Allowed values:

      * ``linux``
      * ``freebsd``

   .. data:: target_binary

      The target binary currently being worked on. This is useful for instance
      in the ROP module.

      .. todo::

         Update documentation with a reference.


      Allowed values are any string.

   .. data:: target_host

      The remote hostname/ip address currently being targeted. Used when
      creating sockets.

      Allowed values are any string.

   .. data:: target_port

      The remote host port currently being targeted. Used when creating sockets.

      Allowed values are any numbers.


   .. data:: endianness

      The default endianness used for e.g. the ``p32`` function. Defaults to
      ``little``.

      .. todo::

         Insert reference.


      Allowed values:

      * ``little``
      * ``big``

   .. data:: word_size

      The default word size used for e.g. the ``flat`` function. Defaults to
      ``32``.

      Allowed values:

      * ``8``
      * ``16``
      * ``32``
      * ``64``

   .. data:: log_level

      The amount of output desired from the :mod:`pwn2.lib.log` module.


      Allowed values:

      * ``debug``
      * ``info``
      * ``error``
      * ``silent``

      Sets the current architecture.

   .. function:: pwn2.lib.context(**kwargs)

      Convenience function, which is shorthand for setting multiple variables at
      once, such that::

        context(a = b, c = d, ...)

      is equivalent to::

        context.a = b
        context.c = d
        ...

      Example usage:

      .. doctest:: test_context

         >>> context(arch = 'i386', os = 'linux')
         >>> print context.arch
         i386

   .. automethod:: pwn2.lib.context.local
   .. automethod:: pwn2.lib.context.reset_local

:mod:`pwn2.lib.context.defaults`
--------------------------------

.. automodule:: pwn2.lib.context.defaults

   The following variables are all the global default equivalents of the
   variables found in the :mod:`pwn2.lib.context` module. They can be read or
   written directly:

   .. data:: arch
   .. data:: net
   .. data:: os
   .. data:: target_binary
   .. data:: target_host
   .. data:: target_port
   .. data:: endianness
   .. data:: word_size
   .. data:: log_level
