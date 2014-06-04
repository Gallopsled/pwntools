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

Some keys further allow aliases, for instance ``arm`` is aliased to ``armel``:

.. doctest:: test_context_alias

    >>> print context.arch
    None
    >>> context.arch = 'arm'
    >>> print context.arch
    armel


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
      AttributeError: Cannot set context-key arch, as the value 'mill' did not validate


   If read, their valued will be looked up in the thread-local dictionary and if
   found returned, otherwise it will default to the global default store. If it
   is not found in the global store either, ``None`` will be returned.

   If writen to, the value will be saved only in the thread-local storage.

   .. exec::
      import pwn2.lib, pwn2.lib.internal
      def prop(s):
          print pwn2.lib.internal.docstring_trim(getattr(pwn2.lib.context.defaults.__class__, s).__doc__)


   .. autodata:: arch

      .. exec::
         prop("arch")

   .. data:: net

      .. exec::
         prop("net")

   .. data:: os


   .. data:: target_binary


   .. data:: target_host

   .. data:: target_port

   .. data:: endianness

   .. data:: word_size


   .. data:: log_level


   .. autofunction:: pwn2.lib.context.__call__(**kwargs)
   .. autofunction:: pwn2.lib.context.local(**kwargs)
   .. autofunction:: pwn2.lib.context.reset_local()

:mod:`pwn2.lib.context.defaults`
--------------------------------

.. automodule:: pwn2.lib.context.defaults

   .. autodata:: arch
   .. data:: net
   .. data:: os
   .. data:: target_binary
   .. data:: target_host
   .. data:: target_port
   .. data:: endianness
   .. data:: word_size
   .. data:: log_level

      These variable are the the global default equivalents of the variables found
      in the :mod:`pwn2.lib.context` module. They work almost exactly the same,
      except for the fact that they are the global defaults, instead of the
      thread-local verions.


   .. autofunction:: pwn2.lib.context.defaults.__call__(**kwargs)


