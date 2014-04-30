__all__ = ['log']

import types, sys

# lazy module loader
class Module(types.ModuleType):
    def __init__ (self):
        self.__file__ = __file__
        self.__name__ = __name__
        self.__path__ = __path__
        self.__all__ = __all__

    def __dir__ (self):
        return self.__all__

    def __getattr__ (self, mod):
        return __import__('pwn2.lib.%s' % mod)

if __name__ <> '__main__':
    sys.modules[__name__] = Module()
