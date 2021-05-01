# -*- coding: utf-8 -*-
"""
Implements context management so that nested/scoped contexts and threaded
contexts work properly and as expected.
"""
from __future__ import absolute_import
from __future__ import division

import collections
import functools
import logging
import os
import platform
import six
import socket
import stat
import string
import subprocess
import sys
import threading
import time

import socks

from pwnlib.config import register_config
from pwnlib.device import Device
from pwnlib.timeout import Timeout

try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable

__all__ = ['context', 'ContextType', 'Thread']

_original_socket = socket.socket

class _devnull(object):
    name = None
    def write(self, *a, **kw): pass
    def read(self, *a, **kw):  return ''
    def flush(self, *a, **kw): pass
    def close(self, *a, **kw): pass

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
        >>> print(t)
        {'key': 'value'}
        >>> def p(): print(t)
        >>> thread = threading.Thread(target=p)
        >>> _ = (thread.start(), thread.join())
        {}
    """
    pass


def _validator(validator):
    """
    Validator that is tightly coupled to the implementation
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
        ...     print(context.arch)
        ...     context.arch = 'mips'
        ...     print(context.arch)
        >>> # Note that a normal Thread starts with a clean context
        >>> # (i386 is the default architecture)
        >>> t = threading.Thread(target=p)
        >>> _=(t.start(), t.join())
        i386
        mips
        >>> # Note that the main Thread's context is unchanged
        >>> print(context.arch)
        arm
        >>> # Note that a context-aware Thread receives a copy of the context
        >>> t = pwnlib.context.Thread(target=p)
        >>> _=(t.start(), t.join())
        arm
        mips
        >>> # Again, the main thread is unchanged
        >>> print(context.arch)
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
        sup = super(Thread, self)
        bootstrap = getattr(sup, '_bootstrap', None)
        if bootstrap is None:
            sup.__bootstrap()
        else:
            bootstrap()
    _bootstrap = __bootstrap

def _longest(d):
    """
    Returns an OrderedDict with the contents of the input dictionary ``d``
    sorted by the length of the keys, in descending order.

    This is useful for performing substring matching via ``str.startswith``,
    as it ensures the most complete match will be found.

    >>> data = {'a': 1, 'bb': 2, 'ccc': 3}
    >>> pwnlib.context._longest(data) == data
    True
    >>> for i in pwnlib.context._longest(data):
    ...     print(i)
    ccc
    bb
    a
    """
    return collections.OrderedDict((k,d[k]) for k in sorted(d, key=len, reverse=True))

class ContextType(object):
    r"""
    Class for specifying information about the target machine.
    Intended for use as a pseudo-singleton through the global
    variable :data:`.context`, available via
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
        ...   print(enhex(pwnlib.asm.asm('nop')))
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
        'adb_host': 'localhost',
        'adb_port': 5037,
        'arch': 'i386',
        'aslr': True,
        'binary': None,
        'bits': 32,
        'buffer_size': 4096,
        'cyclic_alphabet': string.ascii_lowercase.encode(),
        'cyclic_size': 4,
        'delete_corefiles': False,
        'device': os.getenv('ANDROID_SERIAL', None) or None,
        'encoding': 'auto',
        'endian': 'little',
        'gdbinit': "",
        'kernel': None,
        'log_level': logging.INFO,
        'log_file': _devnull(),
        'log_console': sys.stdout,
        'randomize': False,
        'rename_corefiles': True,
        'newline': b'\n',
        'noptrace': False,
        'os': 'linux',
        'proxy': None,
        'ssh_session': None,
        'signed': False,
        'terminal': tuple(),
        'timeout': Timeout.maximum,
    }

    #: Valid values for :meth:`pwnlib.context.ContextType.os`
    oses = sorted(('linux','freebsd','windows','cgc','android','baremetal'))

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
        'none':      {},
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
        self._tls = _Tls_DictStack(_defaultdict(self.defaults))
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

    def local(self, function=None, **kwargs):
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
            >>> print(context.timeout)
            1.0
            >>> with context.local(timeout = 2):
            ...     print(context.timeout)
            ...     context.timeout = 3
            ...     print(context.timeout)
            2.0
            3.0
            >>> print(context.timeout)
            1.0
        """
        class LocalContext(object):
            def __enter__(a):
                self._tls.push()
                self.update(**{k:v for k,v in kwargs.items() if v is not None})
                return self

            def __exit__(a, *b, **c):
                self._tls.pop()

            def __call__(self, function, *a, **kw):
                @functools.wraps(function)
                def inner(*a, **kw):
                    with self:
                        return function(*a, **kw)
                return inner

        return LocalContext()

    @property
    def silent(self, function=None):
        """Disable all non-error logging within the enclosed scope.
        """
        return self.local(function, log_level='error')

    @property
    def quiet(self, function=None):
        """Disables all non-error logging within the enclosed scope,
        *unless* the debugging level is set to 'debug' or lower.

        Example:

            Let's assume the normal situation, where log_level is INFO.

            >>> context.clear(log_level='info')

            Note that only the log levels below ERROR do not print anything.

            >>> with context.quiet:
            ...     log.debug("DEBUG")
            ...     log.info("INFO")
            ...     log.warn("WARN")

            Next let's try with the debugging level set to 'debug' before we
            enter the context handler:

            >>> with context.local(log_level='debug'):
            ...     with context.quiet:
            ...         log.debug("DEBUG")
            ...         log.info("INFO")
            ...         log.warn("WARN")
            [DEBUG] DEBUG
            [*] INFO
            [!] WARN
        """
        level = 'error'
        if context.log_level <= logging.DEBUG:
            level = None
        return self.local(function, log_level=level)

    def quietfunc(self, function):
        """Similar to :attr:`quiet`, but wraps a whole function.

        Example:

            Let's set up two functions, which are the same but one is
            wrapped with :attr:`quietfunc`.

            >>> def loud(): log.info("Loud")
            >>> @context.quietfunc
            ... def quiet(): log.info("Quiet")

            If we set the logging level to 'info', the loud function
            prints its contents.

            >>> with context.local(log_level='info'): loud()
            [*] Loud

            However, the quiet function does not, since :attr:`quietfunc`
            silences all output unless the log level is DEBUG.

            >>> with context.local(log_level='info'): quiet()

            Now let's try again with debugging enabled.

            >>> with context.local(log_level='debug'): quiet()
            [*] Quiet
        """
        @functools.wraps(function)
        def wrapper(*a, **kw):
            level = 'error'
            if context.log_level <= logging.DEBUG:
                level = None
            with self.local(function, log_level=level):
                return function(*a, **kw)
        return wrapper


    @property
    def verbose(self):
        """Enable all logging within the enclosed scope.

        This is the opposite of :attr:`.quiet` and functionally equivalent to:

        .. code-block:: python

            with context.local(log_level='debug'):
                ...

        Example:

            Note that the function does not emit any information by default

            >>> context.clear()
            >>> def func(): log.debug("Hello")
            >>> func()

            But if we put it inside a :attr:`.verbose` context manager, the
            information is printed.

            >>> with context.verbose: func()
            [DEBUG] Hello

        """
        return self.local(log_level='debug')

    def clear(self, *a, **kw):
        """
        Clears the contents of the context.
        All values are set to their defaults.

        Arguments:

            a: Arguments passed to ``update``
            kw: Arguments passed to ``update``

        Examples:

            >>> # Default value
            >>> context.clear()
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

        if a or kw:
            self.update(*a, **kw)

    @property
    def native(self):
        if context.os in ('android', 'baremetal', 'cgc'):
            return False

        arch = context.arch
        with context.local(arch = platform.machine()):
            platform_arch = context.arch

            if arch in ('i386', 'amd64') and platform_arch in ('i386', 'amd64'):
                return True

            return arch == platform_arch

    @_validator
    def arch(self, arch):
        """
        Target binary architecture.

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
        # Lowercase
        arch = arch.lower()

        # Attempt to perform convenience and legacy compatibility transformations.
        # We have to make sure that x86_64 appears before x86 for this to work correctly.
        transform = [('ppc64', 'powerpc64'),
                     ('ppc', 'powerpc'),
                     ('x86_64', 'amd64'),
                     ('x86', 'i386'),
                     ('i686', 'i386'),
                     ('armv7l', 'arm'),
                     ('armeabi', 'arm'),
                     ('arm64', 'aarch64')]
        for k, v in transform:
            if arch.startswith(k):
                arch = v
                break

        try:
            defaults = self.architectures[arch]
        except KeyError:
            raise AttributeError('AttributeError: arch must be one of %r' % sorted(self.architectures))

        for k,v in defaults.items():
            if k not in self._tls:
                self._tls[k] = v

        return arch

    @_validator
    def aslr(self, aslr):
        """
        ASLR settings for new processes.

        If :const:`False`, attempt to disable ASLR in all processes which are
        created via ``personality`` (``setarch -R``) and ``setrlimit``
        (``ulimit -s unlimited``).

        The ``setarch`` changes are lost if a ``setuid`` binary is executed.
        """
        return bool(aslr)

    @_validator
    def kernel(self, arch):
        """
        Target machine's kernel architecture.

        Usually, this is the same as ``arch``, except when
        running a 32-bit binary on a 64-bit kernel (e.g. i386-on-amd64).

        Even then, this doesn't matter much -- only when the the segment
        registers need to be known
        """
        with self.local(arch=arch):
            return self.arch

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
            AttributeError: bits must be > 0 (-1)
        """
        bits = int(bits)

        if bits <= 0:
            raise AttributeError("bits must be > 0 (%r)" % bits)

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
        from pwnlib.elf     import ELF

        if not isinstance(binary, ELF):
            binary = ELF(binary)

        self.arch   = binary.arch
        self.bits   = binary.bits
        self.endian = binary.endian
        self.os     = binary.os

        return binary

    @property
    def bytes(self):
        """
        Target machine word size, in bytes (i.e. the size of general purpose registers).

        This is a convenience wrapper around ``bits // 8``.

        Examples:

            >>> context.bytes = 1
            >>> context.bits == 8
            True

            >>> context.bytes = 0 #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            AttributeError: bits must be > 0 (0)
        """
        return self.bits // 8
    @bytes.setter
    def bytes(self, value):
        self.bits = value*8

    @_validator
    def encoding(self, charset):
        if charset == 'auto':
            return charset

        if (  b'aA'.decode(charset) != 'aA'
            or 'aA'.encode(charset) != b'aA'):
            raise ValueError('Strange encoding!')

        return charset

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

        if endian not in self.endiannesses:
            raise AttributeError("endian must be one of %r" % sorted(self.endiannesses))

        return self.endiannesses[endian]


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
    def log_file(self, value):
        r"""
        Sets the target file for all logging output.

        Works in a similar fashion to :attr:`log_level`.

        Examples:


            >>> foo_txt = tempfile.mktemp()
            >>> bar_txt = tempfile.mktemp()
            >>> context.log_file = foo_txt
            >>> log.debug('Hello!')
            >>> with context.local(log_level='ERROR'): #doctest: +ELLIPSIS
            ...     log.info('Hello again!')
            >>> with context.local(log_file=bar_txt):
            ...     log.debug('Hello from bar!')
            >>> log.info('Hello from foo!')
            >>> open(foo_txt).readlines()[-3] #doctest: +ELLIPSIS
            '...:DEBUG:...:Hello!\n'
            >>> open(foo_txt).readlines()[-2] #doctest: +ELLIPSIS
            '...:INFO:...:Hello again!\n'
            >>> open(foo_txt).readlines()[-1] #doctest: +ELLIPSIS
            '...:INFO:...:Hello from foo!\n'
            >>> open(bar_txt).readlines()[-1] #doctest: +ELLIPSIS
            '...:DEBUG:...:Hello from bar!\n'
        """
        if isinstance(value, (bytes, six.text_type)):
            # check if mode was specified as "[value],[mode]"
            if ',' not in value:
                value += ',a'
            filename, mode = value.rsplit(',', 1)
            value = open(filename, mode)

        elif not hasattr(value, "fileno"):
            raise AttributeError('log_file must be a file')

        # Is this the same file we already have open?
        # If so, don't re-print the banner.
        if self.log_file and not isinstance(self.log_file, _devnull):
            a = os.fstat(value.fileno()).st_ino
            b = os.fstat(self.log_file.fileno()).st_ino

            if a == b:
                return self.log_file

        iso_8601 = '%Y-%m-%dT%H:%M:%S'
        lines = [
            '=' * 78,
            ' Started at %s ' % time.strftime(iso_8601),
            ' sys.argv = [',
            ]
        for arg in sys.argv:
            lines.append('   %r,' % arg)
        lines.append(' ]')
        lines.append('=' * 78)
        for line in lines:
            value.write('=%-78s=\n' % line)
        value.flush()
        return value

    @_validator
    def log_console(self, stream):
        """
        Sets the default logging console target.

        Examples:

            >>> context.log_level = 'warn'
            >>> log.warn("Hello")
            [!] Hello
            >>> context.log_console=open('/dev/null', 'w')
            >>> log.warn("Hello")
            >>> context.clear()
        """
        if isinstance(stream, str):
            stream = open(stream, 'wt')
        return stream

    @property
    def mask(self):
        return (1 << self.bits) - 1

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
            AttributeError: os must be one of ['android', 'baremetal', 'cgc', 'freebsd', 'linux', 'windows']
        """
        os = os.lower()

        if os not in self.oses:
            raise AttributeError("os must be one of %r" % self.oses)

        return os

    @_validator
    def randomize(self, r):
        """
        Global flag that lots of things should be randomized.
        """
        return bool(r)

    @_validator
    def signed(self, signed):
        """
        Signed-ness for packing operation when it's not explicitly set.

        Can be set to any non-string truthy value, or the specific string
        values ``'signed'`` or ``'unsigned'`` which are converted into
        :const:`True` and :const:`False` correspondingly.

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
        try:             signed = self.signednesses[signed]
        except KeyError: pass

        if isinstance(signed, str):
            raise AttributeError('signed must be one of %r or a non-string truthy value' % sorted(self.signednesses))

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
        if isinstance(value, (bytes, six.text_type)):
            return [value]
        return value

    @property
    def abi(self):
        return self._abi

    @_validator
    def proxy(self, proxy):
        """
        Default proxy for all socket connections.

        Accepts either a string (hostname or IP address) for a SOCKS5 proxy on
        the default port, **or** a ``tuple`` passed to ``socks.set_default_proxy``,
        e.g. ``(socks.SOCKS4, 'localhost', 1234)``.

        >>> context.proxy = 'localhost' #doctest: +ELLIPSIS
        >>> r=remote('google.com', 80)
        Traceback (most recent call last):
        ...
        ProxyConnectionError: Error connecting to SOCKS5 proxy localhost:1080: [Errno 111] Connection refused

        >>> context.proxy = None
        >>> r=remote('google.com', 80, level='error')
        """

        if not proxy:
            socket.socket = _original_socket
            return None

        if isinstance(proxy, str):
            proxy = (socks.SOCKS5, proxy)

        if not isinstance(proxy, Iterable):
            raise AttributeError('proxy must be a string hostname, or tuple of arguments for socks.set_default_proxy')

        socks.set_default_proxy(*proxy)
        socket.socket = socks.socksocket

        return proxy

    @_validator
    def noptrace(self, value):
        """Disable all actions which rely on ptrace.

        This is useful for switching between local exploitation with a debugger,
        and remote exploitation (without a debugger).

        This option can be set with the ``NOPTRACE`` command-line argument.
        """
        return bool(value)


    @_validator
    def adb_host(self, value):
        """Sets the target host which is used for ADB.

        This is useful for Android exploitation.

        The default value is inherited from ANDROID_ADB_SERVER_HOST, or set
        to the default 'localhost'.
        """
        return str(value)


    @_validator
    def adb_port(self, value):
        """Sets the target port which is used for ADB.

        This is useful for Android exploitation.

        The default value is inherited from ANDROID_ADB_SERVER_PORT, or set
        to the default 5037.
        """
        return int(value)

    @_validator
    def device(self, device):
        """Sets the device being operated on.
        """
        if isinstance(device, (bytes, six.text_type)):
            device = Device(device)
        if isinstance(device, Device):
            self.arch = device.arch or self.arch
            self.bits = device.bits or self.bits
            self.endian = device.endian or self.endian
            self.os = device.os or self.os
        elif device is not None:
            raise AttributeError("device must be either a Device object or a serial number as a string")

        return device

    @property
    def adb(self):
        """Returns an argument array for connecting to adb.

        Unless ``$ADB_PATH`` is set, uses the default ``adb`` binary in ``$PATH``.
        """
        ADB_PATH = os.environ.get('ADB_PATH', 'adb')

        command = [ADB_PATH]

        if self.adb_host != self.defaults['adb_host']:
            command += ['-H', self.adb_host]

        if self.adb_port != self.defaults['adb_port']:
            command += ['-P', str(self.adb_port)]

        if self.device:
            command += ['-s', str(self.device)]

        return command

    @_validator
    def buffer_size(self, size):
        """Internal buffer size to use for :class:`pwnlib.tubes.tube.tube` objects.

        This is not the maximum size of the buffer, but this is the amount of data
        which is passed to each raw ``read`` syscall (or equivalent).
        """
        return int(size)

    @property
    def cache_dir(self):
        """Directory used for caching data.

        Note:
            May be either a path string, or :const:`None`.

        Example:

            >>> cache_dir = context.cache_dir
            >>> cache_dir is not None
            True
            >>> os.chmod(cache_dir, 0o000)
            >>> context.cache_dir is None
            True
            >>> os.chmod(cache_dir, 0o755)
            >>> cache_dir == context.cache_dir
            True
        """
        xdg_cache_home = os.environ.get('XDG_CACHE_HOME') or \
                         os.path.join(os.path.expanduser('~'), '.cache')

        if not os.access(xdg_cache_home, os.W_OK):
            return None

        cache = os.path.join(xdg_cache_home, '.pwntools-cache-%d.%d' % sys.version_info[:2])

        if not os.path.exists(cache):
            try:
                os.mkdir(cache)
            except OSError:
                return None

        # Some wargames e.g. pwnable.kr have created dummy directories
        # which cannot be modified by the user account (owned by root).
        if not os.access(cache, os.W_OK):
            return None

        return cache

    @_validator
    def delete_corefiles(self, v):
        """Whether pwntools automatically deletes corefiles after exiting.
        This only affects corefiles accessed via :attr:`.process.corefile`.

        Default value is ``False``.
        """
        return bool(v)

    @_validator
    def rename_corefiles(self, v):
        """Whether pwntools automatically renames corefiles.

        This is useful for two things:

        - Prevent corefiles from being overwritten, if ``kernel.core_pattern``
          is something simple like ``"core"``.
        - Ensure corefiles are generated, if ``kernel.core_pattern`` uses ``apport``,
          which refuses to overwrite any existing files.

        This only affects corefiles accessed via :attr:`.process.corefile`.

        Default value is ``True``.
        """
        return bool(v)

    @_validator
    def newline(self, v):
        """Line ending used for Tubes by default.

        This configures the newline emitted by e.g. ``sendline`` or that is used
        as a delimiter for e.g. ``recvline``.
        """
        # circular imports
        from pwnlib.util.packing import _need_bytes
        return _need_bytes(v)


    @_validator
    def gdbinit(self, value):
        """Path to the gdbinit that is used when running GDB locally.

        This is useful if you want pwntools-launched GDB to include some additional modules,
        like PEDA but you do not want to have GDB include them by default.

        The setting will only apply when GDB is launched locally since remote hosts may not have
        the necessary requirements for the gdbinit.

        If set to an empty string, GDB will use the default `~/.gdbinit`.

        Default value is ``""``.
        """
        return str(value)

    @_validator
    def cyclic_alphabet(self, alphabet):
        """Cyclic alphabet.

        Default value is `string.ascii_lowercase`.
        """

        # Do not allow multiple occurrences
        if len(set(alphabet)) != len(alphabet):
            raise AttributeError("cyclic alphabet cannot contain duplicates")

        return alphabet.encode()

    @_validator
    def cyclic_size(self, size):
        """Cyclic pattern size.

        Default value is `4`.
        """
        size = int(size)

        if size > self.bytes:
            raise AttributeError("cyclic pattern size cannot be larger than word size")

        return size

    @_validator
    def ssh_session(self, shell):
        from pwnlib.tubes.ssh import ssh

        if not isinstance(shell, ssh):
            raise AttributeError("context.ssh_session must be an ssh tube") 

        return shell

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


#: Global :class:`.ContextType` object, used to store commonly-used pwntools settings.
#:
#: In most cases, the context is used to infer default variables values.
#: For example, :func:`.asm` can take an ``arch`` parameter as a
#: keyword argument.
#:
#: If it is not supplied, the ``arch`` specified by ``context`` is used instead.
#:
#: Consider it a shorthand to passing ``os=`` and ``arch=`` to every single
#: function call.
context = ContextType()

# Inherit default ADB values
if 'ANDROID_ADB_SERVER_HOST' in os.environ:
    context.adb_host = os.environ.get('ANDROID_ADB_SERVER_HOST')

if 'ANDROID_ADB_SERVER_PORT' in os.environ:
    context.adb_port = int(os.getenv('ANDROID_ADB_SERVER_PORT'))

def LocalContext(function):
    """
    Wraps the specified function on a context.local() block, using kwargs.

    Example:

        >>> context.clear()
        >>> @LocalContext
        ... def printArch():
        ...     print(context.arch)
        >>> printArch()
        i386
        >>> printArch(arch='arm')
        arm
    """
    @functools.wraps(function)
    def setter(*a, **kw):
        with context.local(**{k:kw.pop(k) for k,v in tuple(kw.items()) if isinstance(getattr(ContextType, k, None), property)}):
            arch = context.arch
            bits = context.bits
            endian = context.endian

            # Prevent the user from doing silly things with invalid
            # architecture / bits / endianness combinations.
            if (arch == 'i386' and bits != 32) \
              or (arch == 'amd64' and bits != 64):
                raise AttributeError("Invalid arch/bits combination: %s/%s" % (arch, bits))

            if arch in ('i386', 'amd64') and endian == 'big':
                raise AttributeError("Invalid arch/endianness combination: %s/%s" % (arch, endian))

            return function(*a, **kw)
    return setter

def LocalNoarchContext(function):
    """
    Same as LocalContext, but resets arch to :const:`'none'` by default

    Example:

        >>> @LocalNoarchContext
        ... def printArch():
        ...     print(context.arch)
        >>> printArch()
        none
    """
    @functools.wraps(function)
    def setter(*a, **kw):
        kw.setdefault('arch', 'none')
        with context.local(**{k:kw.pop(k) for k,v in tuple(kw.items()) if isinstance(getattr(ContextType, k, None), property)}):
            return function(*a, **kw)
    return setter

# Read configuration options from the context section
def update_context_defaults(section):
    # Circular imports FTW!
    from pwnlib.util import safeeval
    from pwnlib.log import getLogger
    log = getLogger(__name__)
    for key, value in section.items():
        if key not in ContextType.defaults:
            log.warn("Unknown configuration option %r in section %r" % (key, 'context'))
            continue

        default = ContextType.defaults[key]

        if isinstance(default, six.string_types + six.integer_types + (tuple, list, dict)):
            value = safeeval.expr(value)
        else:
            log.warn("Unsupported configuration option %r in section %r" % (key, 'context'))

        # Attempt to set the value, to see if it is value:
        try:
            with context.local(**{key: value}):
                value = getattr(context, key)
        except (ValueError, AttributeError) as e:
            log.warn("Could not set context.%s=%s via pwn.conf (%s)", key, section[key], e)
            continue

        ContextType.defaults[key] = value

register_config('context', update_context_defaults)
