from types import ModuleType
import importlib, sys
from ...context import context

class module(ModuleType):
    def __init__(self, submodules):
        super(module, self).__init__(__name__)

        # Insert nice properties
        self.__dict__.update({
            '__file__':    __file__,
            '__package__': __package__,
            '__path__':    __path__,
            '__all__':     submodules,
        })

    def __getattr__(self, key):
        if key in self.__all__:
            mod = importlib.import_module('.' + key, __package__)
            setattr(self, key, mod)
            return mod

        if context.arch in self.__all__:
            return getattr(getattr(self, context.arch), key)

        raise AttributeError("'module' object has no attribute '%s'" % key)

    def __dir__(self):
        result = list(self.__all__)
        if context.arch in self.__all__:
            result.extend(dir(getattr(self, context.arch)))


        return result

# To prevent garbage collection
tether = sys.modules[__name__]

# Create the module structure
sys.modules[__name__] = module(['amd64', 'arm', 'i386', 'mips', 'thumb'])
