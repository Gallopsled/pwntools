.. testsetup:: *

   import pwnlib
   from pwnlib import context
   context.reset_local()


:mod:`pwnlib.context` --- Setting runtime variables
=====================================================


:mod:`pwnlib.context`
---------------------

.. automodule:: pwnlib.context

   .. exec::
      import pwnlib
      from inspect import cleandoc
      mod = pwnlib.context.defaults.__class__
      for key in sorted(dir(mod)):
          val = getattr(mod, key)
          if isinstance(val, property):
              print ".. data:: " + key
              print ""
              print cleandoc(val.__doc__)
              print ""

   .. autofunction:: pwnlib.context.__call__(**kwargs)
   .. autofunction:: pwnlib.context.local(**kwargs)
   .. autofunction:: pwnlib.context.reset_local()

:mod:`pwnlib.context.defaults`
------------------------------

.. automodule:: pwnlib.context.defaults

   .. exec::
      import pwnlib
      mod = pwnlib.context.defaults.__class__
      for key in sorted(dir(mod)):
          val = getattr(mod, key)
          if isinstance(val, property):
              print ".. data:: " + key
              print ""
              print "This is the global version of :data:`pwnlib.context.%s`." % key
              print


   .. autofunction:: pwnlib.context.defaults.__call__(**kwargs)



   :mod:`pwn.pwn`
