import types, sys, threading

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
    name = name or updater.func_name
    doc  = doc  or updater.__doc__

    def getter(self):
        try:
            if hasattr(self, '_' + name):
                return getattr(self, '_' + name)
            elif self.defaults:
                return getattr(self.defaults, name)
            else:
                return None
        except BaseException as e:
            print >> sys.stderr, `e`
            print >> sys.stderr, `e`
            print >> sys.stderr, `e`
            raise

    def setter(self, val):
        setattr(self, '_' + name, updater(self, val))

    return property(getter, setter, doc = doc)


def _validator(validator, name = None, doc = None):
    name = name or validator.func_name
    doc  = doc  or validator.__doc__

    def updater(self, val):
        if val == None or validator(self, val):
            return val
        else:
            raise AttributeError('Cannot set context-key %s to %s, did not validate' % (name, val))

    return _updater(updater, name, doc)

def properties():
    keys = [k for k in dir(ContextModule) if k[0] != '_']
    return {k: getattr(ContextModule, k) for k in keys}

class ContextModule(types.ModuleType):
    def __init__(self, defaults = None):
        super(ContextModule, self).__init__(__name__)
        self.defaults = defaults
        self.__dict__.update({
            '__all__'     : [],
            '__file__'    : __file__,
            '__package__' : __package__,
        })

    def __call__(self, **kwargs):
        """This function is the global equivalent of :func:`pwn2.lib.context.__call__`.

        Args:
          **kwargs: Variables to be assigned in the environment."""

        for k, v in kwargs.items():
            setattr(self, k, v)

    @_updater
    def arch(self, value):
        """Variable for the current architecture. This is useful e.g. to make
        :mod:`pwn2.lib.shellcraft` easier to use. Allowed values:

        * ``i386``
        * ``amd64``
        * ``arm`` (alias for armel)
        * ``armel``
        * ``armeb``
        * ``ppc``
        * ``mips``"""

        if value == 'arm':
            return 'armel'
        elif value in ('i386', 'amd64', 'armel', 'armeb', 'ppc', 'mips'):
            return value
        else:
            raise AttributeError('Cannot set context-key arch, as the value %s did not validate' % repr(value))

    @_validator
    def net(self, value):
        """Variable for the current network-stack. This is not currently useful,
        as we only support IPv4, but we'll get there eventually...

        .. todo::

           Update documentation when this changes.

        Allowed values:

        * ``tcp4`` (TCP over IPv4)
        * ``tcp6`` (TCP over IPv6)"""
        return value in ('tcp4', 'tcp6')

    @_validator
    def os(self, value):
        """Variable for the current operating system. This is useful e.g. for
        choosing the right constants for syscall numbers.

        Allowed values:

        * ``linux``
        * ``freebsd``"""
        return value in ('linux', 'freebsd')

    @_validator
    def target_binary(self, value):
        """The target binary currently being worked on. This is useful for
        instance in the ROP module.

        .. todo::

           Update documentation with a reference.

        Allowed values are any string."""

        return type(value) == types.StringType

    @_validator
    def target_host(self, value):
        """The remote hostname/ip address currently being targeted. Used when
        creating sockets.

        Allowed values are any string."""
        return type(value) == types.StringType

    @_validator
    def target_port(self, value):
        """The remote host port currently being targeted. Used when creating
        sockets.

        Allowed values are any numbers in [0, 65535]."""
        return type(value) in [types.IntType, types.LongType] and 0 <= value <= 65535

    @_validator
    def endianness(self, value):
        """The default endianness used for e.g. the ``p32`` function. Defaults
        to ``little``.

        .. todo::

           Fix reference.

        Allowed values:

        * ``little``
        * ``big``"""

        return value in ('big', 'little')

    @_validator
    def sign(self, value):
        """The default signedness used for e.g. the ``p32`` function. Defaults
        to ``unsigned``.

        .. todo::

           Fix reference.

        Allowed values:

        * ``unsigned``
        * ``signed``"""

        return value in ('unsigned', 'signed')

    @_validator
    def word_size(self, value):
        """The default word size used for e.g. the ``flat`` function. Defaults
        to ``32``.

        Allowed values:

        * ``8``
        * ``16``
        * ``32``
        * ``64``"""

        return type(value) not in [types.IntType, types.LongType]

    @_updater
    def log_level(self, value):
        """The amount of output desired from the :mod:`pwn2.lib.log` module.

        Allowed values:

        * ``debug``
        * ``info``
        * ``error``
        * ``silent``"""

        if value in ('debug', 'info', 'error', 'silent'):
            import log
            return getattr(log, value.upper())
        elif type(value) in [types.IntType, types.LongType] or value == None:
            return value
        else:
            raise AttributeError('Cannot set context-key log_level, as the value %s did not validate' % repr(value))


class MainModule(types.ModuleType):
    '''The module for thread-local context variables.'''

    def __init__(self):
        super(MainModule, self).__init__(__name__)
        sys.modules[self.__name__] = self
        self.__dict__.update({
            '__all__'     : ['defaults', 'local', 'reset_local'],
            '__doc__'     : MainModule.__doc__,
            '__file__'    : __file__,
            '__package__' : __package__,
            'defaults'    : ContextModule(),
            '_ctxs'       : {}
        })
        sys.modules[self.__name__ + '.defaults'] = self.defaults

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
          **kwargs: Variables to be assigned in the environment.

        Examples:

          .. doctest:: test_context

             >>> context(arch = 'i386', os = 'linux')
             >>> print context.arch
             i386
"""

        for k, v in kwargs.items():
            setattr(self, k, v)

    def _thread_ctx(self):
        return self._ctxs.setdefault(threading.current_thread().ident, ContextModule(self.defaults))

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
          **kwargs: Variables to be assigned in the new environment.

        Returns:
          Context manager for managing the old and new environment.

        Examples:

          .. doctest:: text_context_local

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
        value from :mod:`pwn2.lib.context.defaults` "shine through".'''
        ctx = self._thread_ctx()
        for k in dir(ctx):
            if k[0] == '_' and k[:2] != '__':
                delattr(ctx, k)

    def __dir__(self):
        res = set(self.__dict__.keys()) | set(dir(self.defaults))
        return sorted(res)


if __name__ <> '__main__':
    # prevent this scope from being GC'ed
    tether = sys.modules[__name__]
    context = MainModule()
