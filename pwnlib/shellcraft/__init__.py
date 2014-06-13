from types import ModuleType
import sys, os, glob

class module(ModuleType):
    def __init__(self, name, directory):
        super(module, self).__init__(name)

        # Insert nice properties
        self.__dict__.update({
            '__file__':    __file__,
            '__package__': __package__,
            '__path__':    __path__,
        })

        # Save the shellcode directory
        self._dir = directory

        # Find the absolute path of the directory
        absdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', directory)

        # Create a dictionary of submodules
        self._submodules = {}
        for name in os.listdir(absdir):
            if os.path.isdir(os.path.join(absdir, name)):
                self._submodules[name] = module(self.__name__ + '.' + name, os.path.join(directory, name))

        # Also put them into top level
        self.__dict__.update(self._submodules)

        # Get the shellcodes and __doc__ from the directory
        self._shellcodes = []
        try:
            with open(os.path.join(absdir, '__doc__')) as fd:
                self.__doc__ = fd.read()
            for f in glob.glob(os.path.join(absdir, '*')):
                f, ext = os.path.splitext(os.path.basename(f))
                self._shellcodes.append(f)
        except IOError:
            pass

        # These are exported
        self.__all__ = self._shellcodes + self._submodules.keys()

        # Insert into the module list
        sys.modules[self.__name__] = self

    def __getattr__(self, key):
        # This function lazy-loads the shellcodes
        if key in self._shellcodes:
            import internal
            real = internal.make_function(key, self._dir)
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
        from pwnlib import context
        for k, m in self._submodules.items():
            if k in [context.arch, context.os, context.net]:
                yield m

    def __shellcodes__(self):
        result = self._shellcodes[:]
        for m in self._context_modules():
            result.extend(m.__shellcodes__())
        return result

# To prevent garbage collection
old_module = sys.modules[__name__]

# Create the module structure
module(__name__, '')
