#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Implements context management so that nested/scoped contexts and threaded
contexts work properly and as expected.
"""
import collections
import logging
import string
import threading

from ..timeout import Timeout


class _defaultdict(dict):
    """
    Dictionary which loads missing keys from another dictionary.

    This is neccesary because the ``default_factory`` method of
    :class:`collections.defaultdict` does not provide the key.

    Examples:

        >>> a = {'foo': 'bar'}
        >>> b = pwnlib.context._defaultdict(a)
        >>> b['foo']
        'bar'
        >>> 'foo' in b
        False
        >>> b['foo'] = 'baz'
        >>> b['foo']
        'baz'
        >>> del b['foo']
        >>> b['foo']
        'bar'

        >>> a = {'foo': 'bar'}
        >>> b = pwnlib.context._defaultdict(a)
        >>> b['baz'] #doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        KeyError: 'baz'
    """
    def __init__(self, default=None):
        super(_defaultdict, self).__init__()
        if default is None:
            default = {}

        self.default = default


    def __missing__(self, key):
        return self.default[key]

class _DictStack(object):
    """
    Manages a dictionary-like object, permitting saving and restoring from
    a stack of states via :func:`push` and :func:`pop`.

    The underlying object used as ``default`` must implement ``copy``, ``clear``,
    and ``update``.

    Examples:

        >>> t = pwnlib.context._DictStack(default={})
        >>> t['key'] = 'value'
        >>> t
        {'key': 'value'}
        >>> t.push()
        >>> t
        {'key': 'value'}
        >>> t['key'] = 'value2'
        >>> t
        {'key': 'value2'}
        >>> t.pop()
        >>> t
        {'key': 'value'}
    """
    def __init__(self, default):
        self._current = _defaultdict(default)
        self.__stack  = []

    def push(self):
        self.__stack.append(self._current.copy())

    def pop(self):
        self._current.clear()
        self._current.update(self.__stack.pop())

    def copy(self):
        return self._current.copy()

    # Pass-through container emulation routines
    def __len__(self):              return self._current.__len__()
    def __delitem__(self, k):       return self._current.__delitem__(k)
    def __getitem__(self, k):       return self._current.__getitem__(k)
    def __setitem__(self, k, v):    return self._current.__setitem__(k, v)
    def __contains__(self, k):      return self._current.__contains__(k)
    def __iter__(self):             return self._current.__iter__()
    def __repr__(self):             return self._current.__repr__()
    def __eq__(self, other):        return self._current.__eq__(other)

    # Required for keyword expansion operator ** to work
    def keys(self):                 return self._current.keys()
    def values(self):               return self._current.values()
    def items(self):                return self._current.items()


class _Tls_DictStack(threading.local, _DictStack):
    """
    Per-thread implementation of :class:`_DictStack`.

    Examples:

        >>> t = pwnlib.context._Tls_DictStack({})
        >>> t['key'] = 'value'
        >>> print t
        {'key': 'value'}
        >>> def p(): print t
        >>> thread = threading.Thread(target=p)
        >>> _ = (thread.start(), thread.join())
        {}
    """
    pass


def _validator(validator):
    """
    Validator that tis tightly coupled to the implementation
    of the classes here.

    This expects that the object has a ._tls property which
    is of type _DictStack.
    """

    name = validator.__name__
    doc  = validator.__doc__

    def fget(self):
        return self._tls[name]

    def fset(self, val):
        self._tls[name] = validator(self, val)

    def fdel(self):
        self._tls._current.pop(name,None)

    return property(fget, fset, fdel, doc)

class Thread(threading.Thread):
    """
    Instantiates a context-aware thread, which inherit its context when it is
    instantiated. The class can be accessed both on the context module as
    `pwnlib.context.Thread` and on the context singleton object inside the
    context module as `pwnlib.context.context.Thread`.

    Threads created by using the native :class`threading`.Thread` will have a
    clean (default) context.

    Regardless of the mechanism used to create any thread, the context
    is de-coupled from the parent thread, so changes do not cascade
    to child or parent.

    Saves a copy of the context when instantiated (at ``__init__``)
    and updates the new thread's context before passing control
    to the user code via ``run`` or ``target=``.

    Examples:

        >>> context.clear()
        >>> context.update(arch='arm')
        >>> def p():
        ...     print context.arch
        ...     context.arch = 'mips'
        ...     print context.arch
        >>> # Note that a normal Thread starts with a clean context
        >>> # (i386 is the default architecture)
        >>> t = threading.Thread(target=p)
        >>> _=(t.start(), t.join())
        i386
        mips
        >>> # Note that the main Thread's context is unchanged
        >>> print context.arch
        arm
        >>> # Note that a context-aware Thread receives a copy of the context
        >>> t = pwnlib.context.Thread(target=p)
        >>> _=(t.start(), t.join())
        arm
        mips
        >>> # Again, the main thread is unchanged
        >>> print context.arch
        arm

    Implementation Details:

        This class implemented by hooking the private function
        :func:`threading.Thread._Thread_bootstrap`, which is called before
        passing control to :func:`threading.Thread.run`.

        This could be done by overriding ``run`` itself, but we would have to
        ensure that all uses of the class would only ever use the keyword
        ``target=`` for ``__init__``, or that all subclasses invoke
        ``super(Subclass.self).set_up_context()`` or similar.
    """
    def __init__(self, *args, **kwargs):
        super(Thread, self).__init__(*args, **kwargs)
        self.old = context.copy()

    def __bootstrap(self):
        """
        Implementation Details:
            This only works because the class is named ``Thread``.
            If its name is changed, we have to implement this hook
            differently.
        """
        context.update(**self.old)
        super(Thread, self).__bootstrap()

def _longest(d):
    """
    Returns an OrderedDict with the contents of the input dictionary ``d``
    sorted by the length of the keys, in descending order.

    This is useful for performing substring matching via ``str.startswith``,
    as it ensures the most complete match will be found.

    >>> data = {'a': 1, 'bb': 2, 'ccc': 3}
    >>> _longest(data) == data
    True
    >>> for i in _longest(data): print i
    ccc
    bb
    a
    """
    return collections.OrderedDict((k,d[k]) for k in sorted(d, key=len, reverse=True))

def TlsProperty(object):
    def __get__(self, obj, objtype=None):
        return obj._tls

class ContextType(object):
    r"""
    Class for specifying information about the target machine.
    Intended for use as a pseudo-singleton through the global
    variable ``pwnlib.context.context``, available via
    ``from pwn import *`` as ``context``.

    The context is usually specified at the top of the Python file for clarity. ::

        #!/usr/bin/env python
        context.update(arch='i386', os='linux')

    Currently supported properties and their defaults are listed below.
    The defaults are inherited from :data:`pwnlib.context.ContextType.defaults`.

    Additionally, the context is thread-aware when using
    :class:`pwnlib.context.Thread` instead of :class:`threading.Thread`
    (all internal ``pwntools`` threads use the former).

    The context is also scope-aware by using the ``with`` keyword.

    Examples:

        >>> context.clear()
        >>> context.update(os='linux') # doctest: +ELLIPSIS
        >>> context.os == 'linux'
        True
        >>> context.arch = 'arm'
        >>> vars(context) == {'arch': 'arm', 'bits': 32, 'endian': 'little', 'os': 'linux'}
        True
        >>> context.endian
        'little'
        >>> context.bits
        32
        >>> def nop():
        ...   print pwnlib.asm.asm('nop').encode('hex')
        >>> nop()
        00f020e3
        >>> with context.local(arch = 'i386'):
        ...   nop()
        90
        >>> from pwnlib.context import Thread as PwnThread
        >>> from threading      import Thread as NormalThread
        >>> with context.local(arch = 'mips'):
        ...     pwnthread = PwnThread(target=nop)
        ...     thread    = NormalThread(target=nop)
        >>> # Normal thread uses the default value for arch, 'i386'
        >>> _=(thread.start(), thread.join())
        90
        >>> # Pwnthread uses the correct context from creation-time
        >>> _=(pwnthread.start(), pwnthread.join())
        00000000
        >>> nop()
        00f020e3
    """

    #
    # Use of 'slots' is a heavy-handed way to prevent accidents
    # like 'context.architecture=' instead of 'context.arch='.
    #
    # Setting any properties on a ContextType object will throw an
    # exception.
    #
    __slots__ = '_tls',

    #: Default values for :class:`pwnlib.context.ContextType`
    defaults = {
        'arch': 'i386',
        'binary': None,
        'bits': 32,
        'endian': 'little',
        'log_level': logging.INFO,
        'newline': '\n',
        'os': 'linux',
        'signed': False,
        'timeout': Timeout.maximum,
        'terminal': None,
    }

    #: Valid values for :meth:`pwnlib.context.ContextType.os`
    oses = sorted(('linux','freebsd','windows'))

    big_32    = {'endian': 'big', 'bits': 32}
    big_64    = {'endian': 'big', 'bits': 64}
    little_8  = {'endian': 'little', 'bits': 8}
    little_16 = {'endian': 'little', 'bits': 16}
    little_32 = {'endian': 'little', 'bits': 32}
    little_64 = {'endian': 'little', 'bits': 64}

    #: Keys are valid values for :meth:`pwnlib.context.ContextType.arch`.
    #
    #: Values are defaults which are set when
    #: :attr:`pwnlib.context.ContextType.arch` is set
    architectures = _longest({
        'aarch64':   little_64,
        'alpha':     little_64,
        'avr':       little_8,
        'amd64':     little_64,
        'arm':       little_32,
        'cris':      little_32,
        'i386':      little_32,
        'ia64':      big_64,
        'm68k':      big_32,
        'mips':      little_32,
        'mips64':    little_64,
        'msp430':    little_16,
        'powerpc':   big_32,
        'powerpc64': big_64,
        's390':      big_32,
        'sparc':     big_32,
        'sparc64':   big_64,
        'thumb':     little_32,
        'vax':       little_32,
    })

    #: Valid values for :attr:`endian`
    endiannesses = _longest({
        'be':     'big',
        'eb':     'big',
        'big':    'big',
        'le':     'little',
        'el':     'little',
        'little': 'little'
    })

    #: Valid string values for :attr:`signed`
    signednesses = {
        'unsigned': False,
        'no':       False,
        'yes':      True,
        'signed':   True
    }

    valid_signed = sorted(signednesses)

    def __init__(self, **kwargs):
        """
        Initialize the ContextType structure.

        All keyword arguments are passed to :func:`update`.
        """
        self._tls = _Tls_DictStack(_defaultdict(ContextType.defaults))
        self.update(**kwargs)


    def copy(self):
        """copy() -> dict
        Returns a copy of the current context as a dictionary.

        Examples:

            >>> context.clear()
            >>> context.os   = 'linux'
            >>> vars(context) == {'os': 'linux'}
            True
        """
        return self._tls.copy()


    @property
    def __dict__(self):
        return self.copy()

    def update(self, *args, **kwargs):
        """
        Convenience function, which is shorthand for setting multiple
        variables at once.

        It is a simple shorthand such that::

            context.update(os = 'linux', arch = 'arm', ...)

        is equivalent to::

            context.os   = 'linux'
            context.arch = 'arm'
            ...

        The following syntax is also valid::

            context.update({'os': 'linux', 'arch': 'arm'})

        Arguments:
          kwargs: Variables to be assigned in the environment.

        Examples:

            >>> context.clear()
            >>> context.update(arch = 'i386', os = 'linux')
            >>> context.arch, context.os
            ('i386', 'linux')
        """
        for arg in args:
            self.update(**arg)

        for k,v in kwargs.items():
            setattr(self,k,v)

    def __repr__(self):
        v = sorted("%s = %r" % (k,v) for k,v in self._tls._current.items())
        return '%s(%s)' % (self.__class__.__name__, ', '.join(v))

    def local(self, **kwargs):
        """local(**kwargs) -> context manager

        Create a context manager for use with the ``with`` statement.

        For more information, see the example below or PEP 343.

        Arguments:
          kwargs: Variables to be assigned in the new environment.

        Returns:
          ContextType manager for managing the old and new environment.

        Examples:

            >>> context.clear()
            >>> context.timeout = 1
            >>> context.timeout == 1
            True
            >>> print context.timeout
            1.0
            >>> with context.local(timeout = 2):
            ...     print context.timeout
            ...     context.timeout = 3
            ...     print context.timeout
            2.0
            3.0
            >>> print context.timeout
            1.0
        """
        class LocalContext(object):
            def __enter__(a):
                self._tls.push()
                self.update(**{k:v for k,v in kwargs.items() if v is not None})
                return self

            def __exit__(a, *b, **c):
                self._tls.pop()

        return LocalContext()

    def clear(self):
        """
        Clears the contents of the context.
        All values are set to their defaults.

        Examples:

            >>> # Default value
            >>> context.arch == 'i386'
            True
            >>> context.arch = 'arm'
            >>> context.arch == 'i386'
            False
            >>> context.clear()
            >>> context.arch == 'i386'
            True
        """
        self._tls._current.clear()

    @_validator
    def arch(self, arch):
        """
        Target machine architecture.

        Allowed values are listed in :attr:`pwnlib.context.ContextType.architectures`.

        Side Effects:

            If an architecture is specified which also implies additional
            attributes (e.g. 'amd64' implies 64-bit words, 'powerpc' implies
            big-endian), these attributes will be set on the context if a
            user has not already set a value.

            The following properties may be modified.

            - :attr:`bits`
            - :attr:`endian`

        Raises:
            AttributeError: An invalid architecture was specified

        Examples:

            >>> context.clear()
            >>> context.arch == 'i386' # Default architecture
            True

            >>> context.arch = 'mips'
            >>> context.arch == 'mips'
            True

            >>> context.arch = 'doge' #doctest: +ELLIPSIS
            Traceback (most recent call last):
             ...
            AttributeError: arch must be one of ['aarch64', ..., 'thumb']

            >>> context.arch = 'ppc'
            >>> context.arch == 'powerpc' # Aliased architecture
            True

            >>> context.clear()
            >>> context.bits == 32 # Default value
            True
            >>> context.arch = 'amd64'
            >>> context.bits == 64 # New value
            True

            Note that expressly setting :attr:`bits` means that we use
            that value instead of the default

            >>> context.clear()
            >>> context.bits = 32
            >>> context.arch = 'amd64'
            >>> context.bits == 32
            True

            Setting the architecture can override the defaults for
            both :attr:`endian` and :attr:`bits`

            >>> context.clear()
            >>> context.arch = 'powerpc64'
            >>> vars(context) == {'arch': 'powerpc64', 'bits': 64, 'endian': 'big'}
            True
        """

        # Lowercase, remove everything non-alphanumeric
        arch = arch.lower()
        arch = arch.replace(string.punctuation, '')

        # Attempt to perform convenience and legacy compatibility
        # transformations.
        transform = {'x86':'i386', 'ppc': 'powerpc', 'x86_64': 'amd64'}
        for k, v in transform.items():
            if arch.startswith(k):
                arch = arch.replace(k,v,1)

        try:
            defaults = ContextType.architectures[arch]
        except KeyError:
            raise AttributeError('AttributeError: arch must be one of %r' % sorted(ContextType.architectures))

        for k,v in ContextType.architectures[arch].items():
            if k not in self._tls:
                self._tls[k] = v

        return arch

    @_validator
    def bits(self, bits):
        """
        Target machine word size, in bits (i.e. the size of general purpose registers).

        The default value is ``32``, but changes according to :attr:`arch`.

        Examples:
            >>> context.clear()
            >>> context.bits == 32
            True
            >>> context.bits = 64
            >>> context.bits == 64
            True
            >>> context.bits = -1 #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            AttributeError: bits must be >= 0 (-1)
        """
        bits = int(bits)

        if bits <= 0:
            raise AttributeError("bits must be >= 0 (%r)" % bits)

        return bits

    @_validator
    def binary(self, binary):
        """
        Infer target architecture, bit-with, and endianness from a binary file.
        Data type is a :class:`pwnlib.elf.ELF` object.

        Examples:

            >>> context.clear()
            >>> context.arch, context.bits
            ('i386', 32)
            >>> context.binary = '/bin/bash'
            >>> context.arch, context.bits
            ('amd64', 64)
            >>> context.binary
            ELF('/bin/bash')

        """
        # Cyclic imports... sorry Idolf.
        from ..elf     import ELF

        e = ELF(binary)

        self.arch   = e.arch
        self.bits   = e.bits
        self.endian = e.endian

        return e

    @property
    def bytes(self):
        """
        Target machine word size, in bytes (i.e. the size of general purpose registers).

        This is a convenience wrapper around ``bits / 8``.

        Examples:

            >>> context.bytes = 1
            >>> context.bits == 8
            True

            >>> context.bytes = 0 #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            AttributeError: bits must be >= 0 (0)
        """
        return self.bits/8
    @bytes.setter
    def bytes(self, value):
        self.bits = value*8


    @_validator
    def endian(self, endianness):
        """
        Endianness of the target machine.

        The default value is ``'little'``, but changes according to :attr:`arch`.

        Raises:
            AttributeError: An invalid endianness was provided

        Examples:

            >>> context.clear()
            >>> context.endian == 'little'
            True

            >>> context.endian = 'big'
            >>> context.endian
            'big'

            >>> context.endian = 'be'
            >>> context.endian == 'big'
            True

            >>> context.endian = 'foobar' #doctest: +ELLIPSIS
            Traceback (most recent call last):
             ...
            AttributeError: endian must be one of ['be', 'big', 'eb', 'el', 'le', 'little']
        """
        endian = endianness.lower()

        if endian not in ContextType.endiannesses:
            raise AttributeError("endian must be one of %r" % sorted(ContextType.endiannesses))

        return ContextType.endiannesses[endian]


    @_validator
    def log_level(self, value):
        """
        Sets the verbosity of ``pwntools`` logging mechanism.

        More specifically it controls the filtering of messages that happens
        inside the handler for logging to the screen. So if you want e.g. log
        all messages to a file, then this attribute makes no difference to you.

        Valid values are specified by the standard Python ``logging`` module.

        Default value is set to ``INFO``.

        Examples:

            >>> context.log_level = 'error'
            >>> context.log_level == logging.ERROR
            True
            >>> context.log_level = 10
            >>> context.log_level = 'foobar' #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            AttributeError: log_level must be an integer or one of ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
        """
        # If it can be converted into an int, success
        try:                    return int(value)
        except ValueError:  pass

        # If it is defined in the logging module, success
        try:                    return getattr(logging, value.upper())
        except AttributeError:  pass

        # Otherwise, fail
        level_names = filter(lambda x: isinstance(x,str), logging._levelNames)
        permitted = sorted(level_names)
        raise AttributeError('log_level must be an integer or one of %r' % permitted)


    @_validator
    def os(self, os):
        """
        Operating system of the target machine.

        The default value is ``linux``.

        Allowed values are listed in :attr:`pwnlib.context.ContextType.oses`.

        Examples:

            >>> context.os = 'linux'
            >>> context.os = 'foobar' #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            AttributeError: os must be one of ['freebsd', 'linux', 'windows']
        """
        os = os.lower()

        if os not in ContextType.oses:
            raise AttributeError("os must be one of %r" % sorted(ContextType.oses))

        return os



    @_validator
    def signed(self, signed):
        """
        Signed-ness for packing operation when it's not explicitly set.

        Can be set to any non-string truthy value, or the specific string
        values ``'signed'`` or ``'unsigned'`` which are converted into
        ``True`` and ``False`` correspondingly.

        Examples:

            >>> context.signed
            False
            >>> context.signed = 1
            >>> context.signed
            True
            >>> context.signed = 'signed'
            >>> context.signed
            True
            >>> context.signed = 'unsigned'
            >>> context.signed
            False
            >>> context.signed = 'foobar' #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            AttributeError: signed must be one of ['no', 'signed', 'unsigned', 'yes'] or a non-string truthy value
        """
        try:             signed = ContextType.signednesses[signed]
        except KeyError: pass

        if isinstance(signed, str):
            raise AttributeError('signed must be one of %r or a non-string truthy value' % sorted(ContextType.signednesses))

        return bool(signed)

    @_validator
    def timeout(self, value=Timeout.default):
        """
        Default amount of time to wait for a blocking operation before it times out,
        specified in seconds.

        The default value is to have an infinite timeout.

        See :class:`pwnlib.timeout.Timeout` for additional information on
        valid values.
        """
        return Timeout(value).timeout

    @_validator
    def terminal(self, value):
        """
        Default terminal used by :meth:`pwnlib.util.misc.run_in_new_terminal`.
        Can be a string or an iterable of strings.  In the latter case the first
        entry is the terminal and the rest are default arguments.
        """
        if isinstance(value, (str, unicode)):
            return [value]
        return value

    #*************************************************************************
    #                               ALIASES
    #*************************************************************************
    #
    # These fields are aliases for fields defined above, either for
    # convenience or compatibility.
    #
    #*************************************************************************

    def __call__(self, **kwargs):
        """
        Alias for :meth:`pwnlib.context.ContextType.update`
        """
        return self.update(**kwargs)

    def reset_local(self):
        """
        Deprecated.  Use :meth:`clear`.
        """
        self.clear()

    @property
    def endianness(self):
        """
        Legacy alias for :attr:`endian`.

        Examples:

            >>> context.endian == context.endianness
            True
        """
        return self.endian
    @endianness.setter
    def endianness(self, value):
        self.endian = value


    @property
    def sign(self):
        """
        Alias for :attr:`signed`
        """
        return self.signed

    @sign.setter
    def sign(self, value):
        self.signed = value

    @property
    def signedness(self):
        """
        Alias for :attr:`signed`
        """
        return self.signed

    @signedness.setter
    def signedness(self, value):
        self.signed = value


    @property
    def word_size(self):
        """
        Alias for :attr:`bits`
        """
        return self.bits

    @word_size.setter
    def word_size(self, value):
        self.bits = value

    Thread = Thread


#: Global ``context`` object, used to store commonly-used pwntools settings.
#: In most cases, the context is used to infer default variables values.
#: For example, :meth:`pwnlib.asm.asm` can take an ``os`` parameter as a
#: keyword argument.  If it is not supplied, the ``os`` specified by
#: ``context`` is used instead.
#: Consider it a shorthand to passing ``os=`` and ``arch=`` to every single
#: function call.
context = ContextType()
