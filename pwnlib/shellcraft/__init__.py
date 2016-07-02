import os
import re
import sys
from types import ModuleType

from . import internal
from .. import constants
from ..context import context
from ..util import packing


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
        self._absdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', self._dir)

        # Get the docstring
        with open(os.path.join(self._absdir, "__doc__")) as fd:
            self.__doc__ = fd.read()

        # Insert into the module list
        sys.modules[self.__name__] = self

    def _get_source(self, template):
        assert template in self.templates
        return os.path.join(self._absdir, *template.split('.')) + '.asm'

    def __lazyinit__(self):

        # Create a dictionary of submodules
        self._submodules = {}
        self._shellcodes = {}
        for name in os.listdir(self._absdir):
            path = os.path.join(self._absdir, name)
            if os.path.isdir(path):
                self._submodules[name] = module(self.__name__ + '.' + name, os.path.join(self._dir, name))
            elif os.path.isfile(path) and name != '__doc__' and name[0] != '.':
                funcname, _ext = os.path.splitext(name)
                if not re.match('^[a-zA-Z][a-zA-Z0-9_]*$', funcname):
                    raise ValueError("found illegal filename, %r" % name)
                self._shellcodes[funcname] = name

        # Put the submodules into toplevel
        self.__dict__.update(self._submodules)

        # These are exported
        self.__all__ = sorted(self._shellcodes.keys() + self._submodules.keys())

        # Make sure this is not called again
        self.__lazyinit__ = None

    def __getattr__(self, key):
        self.__lazyinit__ and self.__lazyinit__()

        # Maybe the lazyinit added it
        if key in self.__dict__:
            return self.__dict__[key]

        # This function lazy-loads the shellcodes
        if key in self._shellcodes:
            real = internal.make_function(key, self._shellcodes[key], self._dir)
            setattr(self, key, real)
            return real

        for m in self._context_modules():
            try:
                return getattr(m, key)
            except AttributeError:
                pass

        raise AttributeError("'module' object has no attribute '%s'" % key)

    def __dir__(self):
        # This function lists the available submodules, available shellcodes
        # and potentially shellcodes available in submodules that should be
        # avilable because of the context
        self.__lazyinit__ and self.__lazyinit__()

        result = list(self._submodules.keys())
        result.extend(('__file__', '__package__', '__path__',
                       '__all__',  '__name__'))
        result.extend(self.__shellcodes__())

        return result

    def _context_modules(self):
        self.__lazyinit__ and self.__lazyinit__()
        for k, m in self._submodules.items():
            if k in [context.arch, context.os]:
                yield m

    def __shellcodes__(self):
        self.__lazyinit__ and self.__lazyinit__()
        result = self._shellcodes.keys()
        for m in self._context_modules():
            result.extend(m.__shellcodes__())
        return result

    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    templates    = []

    for root, subfolder, files in os.walk(template_dir):
        for file in filter(lambda x: x.endswith('.asm'), files):
            value = os.path.splitext(file)[0]
            value = os.path.join(root, value)
            value = value.replace(template_dir, '')
            value = value.replace(os.path.sep, '.')
            value = value.lstrip('.')
            templates.append(value)

    templates = sorted(templates)

    def eval(self, item):
        if isinstance(item, (int,long)):
            return item
        return constants.eval(item)

    def pretty(self, n, comment=True):
        if isinstance(n, str):
            return repr(n)
        if not isinstance(n, int):
            return n
        if isinstance(n, constants.Constant):
            if comment: return '%s /* %s */' % (n,self.pretty(int(n)))
            else:       return '%s (%s)'     % (n,self.pretty(int(n)))
        elif abs(n) < 10:
            return str(n)
        else:
            return hex(n)

    def okay(self, s, *a, **kw):
        if isinstance(s, int):
            s = packing.pack(s, *a, **kw)
        return '\0' not in s and '\n' not in s

    import registers

# To prevent garbage collection
tether = sys.modules[__name__]

# Create the module structure
shellcraft = module(__name__, '')

class LazyImporter:
    def find_module(self, fullname, path):
        if not fullname.startswith('pwnlib.shellcraft.'):
            return None

        parts = fullname.split('.')[2:]
        cur = shellcraft
        for part in parts:
            cur = getattr(cur, part, None)
            if not isinstance(cur, ModuleType):
                return None

        return self

    def load_module(self, fullname):
        return sys.modules[fullname]
sys.meta_path.append(LazyImporter())
