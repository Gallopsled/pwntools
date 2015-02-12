"""Module containing constants extracted from header files.

The purpose of this module is to provide quick access to constants from
different architectures and operating systems.

Example:

    >>> print constants.freebsd.SYS_stat
    188
    >>> print constants.linux.i386.SYS_stat
    106
    >>> print constants.linux.amd64.SYS_stat
    4

The submodule ``freebsd`` contains all constants for FreeBSD, while the
constants for Linux have been split up by architecture.

The variables of the submodules will be "lifted up" by setting the
:data:`pwnlib.context.arch` or :data:`pwnlib.context.os` in a manner similar to
what happens in :mod:`pwnlib.shellcraft`.

Example:

    >>> with context.local(os = 'freebsd'):
    ...     print constants.SYS_stat
    188
    >>> with context.local(os = 'linux', arch = 'i386'):
    ...     print constants.SYS_stat
    106
    >>> with context.local(os = 'linux', arch = 'amd64'):
    ...     print constants.SYS_stat
    4

"""
import importlib
import sys
from types import ModuleType

from ..context import context
from ..util import safeeval


class module(ModuleType):
    def __init__(self, submodules):
        super(module, self).__init__(__name__)

        # Insert nice properties
        self.__dict__.update({
            '__doc__':     __doc__,
            '__file__':    __file__,
            '__package__': __package__,
            '__path__':    __path__,
            '__all__':     submodules,
        })

        self._env_store = {}

    def __getattr__(self, key):
        if key in self.__all__:
            mod = importlib.import_module('.' + key, __package__)
            setattr(self, key, mod)
            return mod

        if context.os in self.__all__:
            return getattr(getattr(self, context.os), key)

        raise AttributeError("'module' object has no attribute '%s'" % key)

    def __dir__(self):
        result = list(self.__all__)
        if context.os in self.__all__:
            result.extend(dir(getattr(self, context.os)))

        return result

    def eval(self, string):
        """eval(string) -> value

        Evaluates a string in the context of values of this module.

        Example:

            >>> with context.local(arch = 'i386', os = 'linux'):
            ...    print constants.eval('SYS_execve + PROT_WRITE')
            13
            >>> with context.local(arch = 'amd64', os = 'linux'):
            ...    print constants.eval('SYS_execve + PROT_WRITE')
            61
            >>> with context.local(arch = 'amd64', os = 'linux'):
            ...    print constants.eval('SYS_execve + PROT_WRITE')
            61
        """
        if isinstance(string, int):
            return string

        key = context.os, context.arch
        if key not in self._env_store:
            self._env_store[key] = {key: getattr(self, key) for key in dir(self) if not key.endswith('__')}

        return safeeval.values(string, self._env_store[key])

# To prevent garbage collection
tether = sys.modules[__name__]

# Create the module structure
sys.modules[__name__] = module(['linux', 'freebsd'])
