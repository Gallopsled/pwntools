#from types import ModuleType
#import sys, os, glob, imp
#
#class module(ModuleType):
#    def __init__(self, name):
#        super(module, self).__init__(name)
#
#        # Insert nice properties
#        self.__dict__.update({
#            '__file__':    __file__,
#            '__package__': __package__,
#            '__path__':    __path__,
#        })
#
#        # Find the absolute path of the directory
#        absdir = os.path.abspath(os.path.dirname(__file__))
#
#        # Create a dictionary of submodules
#        self._submodules = {}
#        for name in os.listdir(absdir):
#            if name == 'genconstants':
#                continue
#            dir_path = os.path.join(absdir, name)
#            if os.path.isdir(dir_path):
#                self._submodules[name] = const(self.__name__ + '.' + name, os.path.join(absdir, name))
#
#        # Also put them into top level
#        self.__dict__.update(self._submodules)
#
#        # These are exported
#        self.__all__ = self._submodules.keys()
#
#        # Insert into the module list
#        sys.modules[self.__name__] = self
#
#    def __getattr__(self, key):
#        for m in self._submodules:
#            try:
#                return getattr(m, key)
#            except AttributeError as e:
#                pass
#
#        raise AttributeError("'module' object has no attribute '%s'" % key)
#
#    def __dir__(self):
#        # This function lists the available submodules, available shellcodes
#        # and potentially shellcodes available in submodules that should be
#        # avilable because of the context
#        result = list(self._submodules.keys())
#        result.extend(('__file__', '__package__', '__path__',
#                       '__all__',  '__name__'))
#
#        return result
#
#class const(ModuleType):
#    def __init__(self, name, directory):
#        super(const, self).__init__(name)
#        # Insert nice properties
#        self.__dict__.update({
#            '__file__':    __file__,
#            '__package__': __package__,
#            '__path__':    __path__,
#        })
#        self._submodules = {}
#
#        # Load the constants in the submodules
#        for filename in glob.glob(os.path.join(directory, '*.py')):
#            with open(filename) as f:
#                code = f.read()
#            basename, ext = os.path.splitext(os.path.basename(filename))
#            self._submodules[basename] = imp.new_module(name)
#            exec code in self._submodules[basename].__dict__
#            sys.modules[name + '.' + basename] = self._submodules[basename]
#
#        sys.modules[self.__name__] = self
#
#
#    def __getattr__(self, key):
#        try:
#            return self._submodules[key]
#        except KeyError as e:
#            raise AttributeError("'module' object has no attribute '%s'" % key)
#
#    def __dir__(self):
#        # This function lists the available submodules, available shellcodes
#        # and potentially shellcodes available in submodules that should be
#        # avilable because of the context
#        result = list(self._submodules.keys())
#        result.extend(('__file__', '__package__', '__path__',
#                       '__all__',  '__name__'))
#
#        return result
#
## To prevent garbage collection
#tether = sys.modules[__name__]
#
## Create the module structure
#module(__name__)
