from types import ModuleType
import sys, os

context = []

class module(ModuleType):
    def __init__(self, name = '.', submodules = (), shellcodes = {}):
        super(module, self).__init__((__name__ + '.' + name).strip('.'))

        # Insert nice properties
        self.__dict__.update({
            '__file__':    __file__,
            '__package__': __package__,
            '__path__':    __path__,
        })

        # The relative directory to look up shellcodes in
        self._dir = os.path.join('.', *name.split('.'))

        # Create a dictionary of submodules
        self._submodules = {}
        for m in submodules:
            self._submodules[m.__name__.split('.')[-1]] = m

        # Also put them into top level
        self.__dict__.update(self._submodules)

        # Save the submodules
        self._shellcodes  = shellcodes

        # These are exported
        self.__all__ = self._shellcodes.keys() + self._submodules.keys()

        # Insert into the module list
        sys.modules[self.__name__] = self

    def __getattr__(self, key):
        # This function lazy-loads the shellcodes
        if key in self._shellcodes:
            import internal
            real = internal.make_function(key, self._dir, self._shellcodes[key])
            setattr(self, key, real)
            return real

        for m in self._context_modules():
            try:
                return getattr(m, key)
            except AttributeError as e:
                pass

        raise AttributeError

    def __dir__(self):
        # This function lists the available submodules, available shellcodes
        # and potentially shellcodes available in submodules that should be
        # avilable because of the context
        result = list(self._submodules.keys())
        result.extend(('__file__', '__package__', '__path__',
                       '__all__',  '__name__'))
        result.extend(self.__shellcodes__())

        return result

    def _context_modules(self):
        for k, m in self._submodules.items():
            if k in context:
                yield m

    def __shellcodes__(self):
        result = list(self._shellcodes.keys())
        for m in self._context_modules():
            result.extend(m.__shellcodes__())
        return result

# To prevent garbage collection
old_module = sys.modules[__name__]

module(submodules = (
    module('i386', shellcodes = {
        'pushstr':    'pushstr.asm',
        'breakpoint': 'misc.asm',
        'infloop':    'misc.asm',
        'nop':        'misc.asm',
    }),
))
