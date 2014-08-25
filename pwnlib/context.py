import types, sys, threading
from . import log_levels

# These attributes are set on the defaults module after it have been constructed
# If you change any of these values, remember to update the docstring.
defaults = {
    'endianness': 'little',
    'sign': 'unsigned',
    'word_size': 32,
    'log_level': 'error',
    '__doc__': '''The global default-version of :mod:`pwnlib.context`.

For at description see :mod:`pwnlib.context`. This is the global defaults, that
act as a "base" for the thread-local values.
'''}

# These are the possiblities for arch and os
__possible__ = {
    'arch': (
        'alpha', 'amd64', 'arm', 'armeb',
        'cris', 'i386', 'm68k', 'mips',
        'mipsel', 'powerpc', 'thumb'
    ),
    'arch32': ('arm', 'armeb', 'cris', 'i386', 'm68k', 'mips', 'mipsel', 'thumb'),
    'arch64': ('alpha', 'amd64'),
    'os': ('linux', 'freebsd')
}

class Local(object):
    def __init__(self, args):
        self.args = args

    def __enter__(self):
        self.saved = context._thread_ctx().__dict__.copy()
        for k, v in self.args.items():
            setattr(context, k, v)

    def __exit__(self, *args):
        context._thread_ctx().__dict__.clear()
        context._thread_ctx().__dict__.update(self.saved)

def _updater(updater, name = None, doc = None):
    name = name or updater.__name__
    doc  = doc  or updater.__doc__

    def getter(self):
        if hasattr(self, '_' + name):
            return getattr(self, '_' + name)
        elif self.defaults:
            return getattr(self.defaults, name)
        else:
            return None

    def setter(self, val):
        setattr(self, '_' + name, updater(self, val))

    # Setting _inner is a slight hack only used to get better documentation
    res = property(getter, setter, doc = doc)
    res.fget._inner = updater
    return res

def _validator(validator, name = None, doc = None):
    name = name or validator.__name__
    doc  = doc  or validator.__doc__

    def updater(self, val):
        if val == None or validator(self, val):
            return val
        else:
            raise AttributeError(
                'Cannot set context-key %s to %s, did not validate' % \
                  (name, val)
            )

    # Setting _inner is a slight hack only used to get better documentation
    res = _updater(updater, name, doc)
    res.fget._inner = validator
    return res

def properties():
    keys = [k for k in dir(ContextModule) if k[0] != '_']
    return {k: getattr(ContextModule, k) for k in keys}

class ContextModule(types.ModuleType):
    def __init__(self, defaults = None):
        super(ContextModule, self).__init__(__name__)
        self.defaults     = defaults
        self.__possible__ = __possible__
        self.__dict__.update({
            '__all__'     : [],
            '__file__'    : __file__,
            '__package__' : __package__,
        })

    def __call__(self, **kwargs):
        """This function is the global equivalent of
        :func:`pwnlib.context.__call__`.

        Args:
          kwargs: Variables to be assigned in the environment."""

        for k, v in kwargs.items():
            setattr(self, k, v)

    @_validator
    def arch(self, value):
        """Variable for the current architecture. This is useful e.g. to make
        :mod:`pwnlib.shellcraft` easier to use. Allowed values:

        * ``alpha``
        * ``amd64``
        * ``arm``
        * ``armeb``
        * ``cris``
        * ``i386``
        * ``m68k``
        * ``mips``
        * ``mipsel``
        * ``powerpc``
        * ``thumb``

        Setting this will also update :data:`pwnlib.context.word_size`.
        """

        if value in self.__possible__['arch']:
            if value in self.__possible__['arch32']:
                self.word_size = 32
            elif value in self.__possible__['arch64']:
                self.word_size = 64
            return value

    @_validator
    def os(self, value):
        """Variable for the current operating system. This is useful e.g. for
        choosing the right constants for syscall numbers.

        Allowed values:

        * ``linux``
        * ``freebsd``"""

        if value in self.__possible__['os']:
            return value

    @_validator
    def endianness(self, value):
        """The default endianness used for e.g. the
        :func:`pwnlib.util.packing.pack` function. Defaults to ``little``.

        Allowed values:

        * ``little``
        * ``big``"""

        return value in ('big', 'little')

    @_validator
    def sign(self, value):
        """The default signedness used for e.g. the
        :func:`pwnlib.util.packing.pack` function. Defaults to ``unsigned``.

        Allowed values:

        * ``unsigned``
        * ``signed``"""

        return value in ('unsigned', 'signed')

    @_validator
    def timeout(self, value):
        """The default timeout used by e.g. :class:`pwnlib.tubes.ssh`.

        Defaults to None, meaning no timeout.

        Allowed values are any strictly positive number or None."""

        return type(value) in [types.IntType,
                               types.LongType,
                               types.FloatType] and value >= 0

    @_validator
    def word_size(self, value):
        """The default word size used for e.g. the
        :func:`pwnlib.util.packing.pack` function. Defaults to ``32``.

        Allowed values are any strictly positive number."""

        return type(value) in [types.IntType, types.LongType] and value > 0

    @_updater
    def log_level(self, value):
        """The amount of output desired from the :mod:`pwnlib.log` module.

        Allowed values are any numbers or a string.

        If a string is given, we uppercase the string and lookup it
        up in the log module.

        E.g if ``'debug'`` is specified, then the result is ``10``, as
        :data:`pwnlib.log_levels.DEBUG` is ``10``.
"""

        if type(value) in [types.IntType, types.LongType, types.NoneType]:
            return value
        elif type(value) == types.StringType:
            if hasattr(log_levels, value.upper()):
                return getattr(log_levels, value.upper())

        raise AttributeError(
            'Cannot set context-key log_level, ' +
            'as the value %r did not validate' % value
        )

    def __dir__(self):
        res = set(dir(super(ContextModule, self))) | set(properties().keys())
        if self.defaults:
            res |= set(dir(self.defaults))
        return sorted(res)


class MainModule(types.ModuleType):
    '''The module for thread-local context variables.

The purpose of this module is to store runtime configuration of pwntools, such
as the level of logging or the default architecture for shellcode.

It is implemented as a restricted dictionary, with a predefined number of
keys and with each key having restrictions of which values it will allow.

The values are available both in a thread-local version and as a global
default. You are able to read or write each version separately. If you try to
read from the thread-local version, and no value is found, then the global
default is checked.

The module :mod:`pwnlib.context` is for accessing the thread-local version,
while the global defaults are available in :mod:`pwnlib.context.defaults`.

.. note::

   Ideally, we would want to clone the thread-local context on thread creation,
   but do not know of a way to hook thread creation.

The variables in this module can be read or written directly. If you try to
write an invalid value, an exception is thrown:

.. doctest:: context_example

   >>> print context.arch
   None
   >>> context.arch = 'i386'
   >>> print context.arch
   i386
   >>> context.arch = 'mill'
   Traceback (most recent call last):
       ...
   AttributeError: Cannot set context-key arch, as the value 'mill' did not validate

For a few variables, a slight translation occur when you try to set the
variable. An example of this is :data:`pwnlib.context.log_level`:

.. doctest:: context_log_level

   >>> context.log_level = 33
   >>> print context.log_level
   33
   >>> context.log_level = 'debug'
   >>> print context.log_level
   10

In this case the translation is done by looking up the string in
:mod:`pwnlib.log`, so the result happens because :data:`pwnlib.log_levels.DEBUG`
is ``10``.

A read can never throw an exception. If there is no result in the thread-local
dictionary, the global dictionary is queried. If it has no results either,
``None`` is returned.
'''

    def __init__(self):
        super(MainModule, self).__init__(__name__)
        sys.modules[self.__name__] = self
        self.__dict__.update({
            '__all__'     : ['defaults', 'local', 'reset_local'],
            '__doc__'     : MainModule.__doc__,
            '__file__'    : __file__,
            '__package__' : __package__,
            'defaults'    : ContextModule(),
            '_ctxs'       : {},
        })
        sys.modules[self.__name__ + '.defaults'] = self.defaults
        for k, v in defaults.items():
            setattr(self.defaults, k, v)

    def __call__(self, **kwargs):
        """Convenience function, which is shorthand for setting multiple
        variables at once.

        It is a simple shorthand such that::

            context(a = b, c = d, ...)

        is equivalent to::

            context.a = b
            context.c = d
            ...

        Args:
          kwargs: Variables to be assigned in the environment.

        Examples:

          .. doctest:: context

             >>> context(arch = 'i386', os = 'linux')
             >>> print context.arch
             i386
"""

        for k, v in kwargs.items():
            setattr(self, k, v)

    def _thread_ctx(self):
        return self._ctxs.setdefault(
            threading.current_thread().ident, ContextModule(self.defaults)
        )

    def __getattr__(self, key):
        return getattr(self._thread_ctx(), key)

    def __setattr__(self, key, value):
        setattr(self._thread_ctx(), key, value)

    def local(self, **kwargs):
        '''Create a new thread-local context.

        This function creates a `context manager <https://docs.python.org/2/reference/compound_stmts.html#the-with-statement>`_,
        which will create a new environment upon entering and restore the old
        environment upon exiting.

        As a convenience, it also accepts a number of kwarg-style arguments for
        settings variables in the newly created environment.

        Args:
          kwargs: Variables to be assigned in the new environment.

        Returns:
          Context manager for managing the old and new environment.

        Examples:

          .. doctest:: context_local

             >>> print context.arch
             None
             >>> with context.local(arch = 'i386'):
             ...     print context.arch
             ...     context.arch = 'mips'
             ...     print context.arch
             i386
             mips
             >>> print context.arch
             None
'''

        return Local(kwargs)

    def reset_local(self):
        '''Completely clears the current thread-local context, thus making the
        value from :mod:`pwnlib.context.defaults` "shine through".'''
        ctx = self._thread_ctx()
        for k in dir(ctx):
            if k[0] == '_' and k[:2] != '__' and hasattr(ctx, k):
                delattr(ctx, k)

    def __dir__(self):
        res = set(dir(super(MainModule, self))) | set(dir(self._thread_ctx()))
        return sorted(res)

# prevent this scope from being GC'ed
tether = sys.modules[__name__]
context = MainModule()
