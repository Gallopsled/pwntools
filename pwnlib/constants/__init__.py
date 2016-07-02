"""Module containing constants extracted from header files.

The purpose of this module is to provide quick access to constants from
different architectures and operating systems.

The constants are wrapped by a convenience class that allows accessing
the name of the constant, while performing all normal mathematical
operations on it.

Example:

    >>> str(constants.freebsd.SYS_stat)
    'SYS_stat'
    >>> int(constants.freebsd.SYS_stat)
    188
    >>> hex(constants.freebsd.SYS_stat)
    '0xbc'
    >>> 0 | constants.linux.i386.SYS_stat
    106
    >>> 0 + constants.linux.amd64.SYS_stat
    4

The submodule ``freebsd`` contains all constants for FreeBSD, while the
constants for Linux have been split up by architecture.

The variables of the submodules will be "lifted up" by setting the
:data:`pwnlib.context.arch` or :data:`pwnlib.context.os` in a manner similar to
what happens in :mod:`pwnlib.shellcraft`.

Example:

    >>> with context.local(os = 'freebsd'):
    ...     print int(constants.SYS_stat)
    188
    >>> with context.local(os = 'linux', arch = 'i386'):
    ...     print int(constants.SYS_stat)
    106
    >>> with context.local(os = 'linux', arch = 'amd64'):
    ...     print int(constants.SYS_stat)
    4

"""
import importlib
import sys
from types import ModuleType

from ..context import context
from ..util import safeeval
from .constant import Constant


class ConstantsModule(ModuleType):
    """
    ModuleType specialization in order to automatically
    route queries down to the correct module based on the
    current context arch / os.

        >>> with context.local(arch = 'i386', os = 'linux'):
        ...    print constants.SYS_execve + constants.PROT_WRITE
        13
        >>> with context.local(arch = 'amd64', os = 'linux'):
        ...    print constants.SYS_execve + constants.PROT_WRITE
        61
        >>> with context.local(arch = 'amd64', os = 'linux'):
        ...    print constants.SYS_execve + constants.PROT_WRITE
        61
        >>> False
        True

    """
    Constant = Constant

    possible_submodules = set(context.oses) | set(context.architectures)

    def __init__(self, name, module):
        super(ConstantsModule, self).__init__(name)
        self.__dict__.update(module.__dict__)
        self._env_store = {}

    def guess(self):
        if context.os in self.__name__ and context.arch in self.__name__:
            return self

        mod = self
        mod = getattr(mod, context.os, mod)
        mod = getattr(mod, context.arch, mod)
        return mod

    def __dir__(self):
        return self.__all__

    def __getattr__(self, key):
        # Special case for __all__, we want to return the contextually
        # relevant module.
        if key == '__all__':
            return self.guess().__dict__.keys()

        # Special case for all other special properties which aren't defined
        if key.endswith('__'):
            raise AttributeError

        # This code is only hit if the attribute doesn't already exist.
        # Attempt to import a module by the specified name.
        if key in self.possible_submodules:
            try:
                mod = importlib.import_module('.' + key, self.__name__)
                mod = ConstantsModule(mod.__name__, mod)
                setattr(self, key, mod)
                sys.modules[mod.__name__] = mod
                return mod
            except ImportError:
                pass
        else:
            mod = self.guess()
            if hasattr(mod, key):
                return getattr(mod, key)

        raise AttributeError("'module' object has no attribute '%s'" % key)

    def eval(self, string):
        """eval(string) -> value

        Evaluates a string in the context of values of this module.

        Example:

            >>> with context.local(arch = 'i386', os = 'linux'):
            ...    print 13 == constants.eval('SYS_execve + PROT_WRITE')
            True
            >>> with context.local(arch = 'amd64', os = 'linux'):
            ...    print 61 == constants.eval('SYS_execve + PROT_WRITE')
            True
            >>> with context.local(arch = 'amd64', os = 'linux'):
            ...    print 61 == constants.eval('SYS_execve + PROT_WRITE')
            True
        """
        if not isinstance(string, str):
            return string

        key = context.os, context.arch
        if key not in self._env_store:
            self._env_store[key] = {key: getattr(self, key) for key in dir(self) if not key.endswith('__')}

        return Constant('(%s)' % string, safeeval.values(string, self._env_store[key]))


# To prevent garbage collection
tether = sys.modules[__name__]

# Create the module structure
sys.modules[__name__] = ConstantsModule(__name__, tether)
