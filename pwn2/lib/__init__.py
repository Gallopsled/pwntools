__all__ = ['log', 'context']

import types, sys, exception

# lazy module loader
class Module(types.ModuleType):
    def __init__ (self):
        self.__file__ = __file__
        self.__name__ = __name__
        self.__path__ = __path__
        self.__all__ = __all__
        self.PwnlibException = exception.PwnlibException

    def __dir__ (self):
        return self.__all__ + ['PwnlibException']

    def __getattr__ (self, mod):
        import sys
        modstr = 'pwn2.lib.%s' % mod
        __import__(modstr)
        modobj = sys.modules[modstr]
        setattr(self, mod, modobj)
        return modobj

if __name__ <> '__main__':
    sys.modules[__name__] = Module()
