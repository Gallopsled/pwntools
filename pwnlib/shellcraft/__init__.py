from __future__ import absolute_import
from __future__ import division

import itertools
import os
import re
import six
import sys
from types import ModuleType

from pwnlib import constants
from pwnlib.context import context
from pwnlib.shellcraft import internal
from pwnlib.util import packing


class module(ModuleType):
    _templates = []

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
                if not re.match('^[a-zA-Z_][a-zA-Z0-9_]*$', funcname):
                    raise ValueError("found illegal filename, %r" % name)
                self._shellcodes[funcname] = name

        # Put the submodules into toplevel
        self.__dict__.update(self._submodules)

        # These are exported
        self.__all__ = sorted(itertools.chain(self._shellcodes.keys(), self._submodules.keys()))

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
            if k in [context.arch, context.os, 'syscalls']:
                yield m

    def __shellcodes__(self):
        self.__lazyinit__ and self.__lazyinit__()
        result = list(self._shellcodes.keys())
        for m in self._context_modules():
            result.extend(m.__shellcodes__())
        return result

    @property
    def templates(self):
        if self._templates:
            return self._templates

        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        templates    = []

        for root, _, files in os.walk(template_dir, followlinks=True):
            for file in filter(lambda x: x.endswith('.asm'), files):
                value = os.path.splitext(file)[0]
                value = os.path.join(root, value)
                value = value.replace(template_dir, '')
                value = value.replace(os.path.sep, '.')
                value = value.lstrip('.')
                templates.append(value)

        templates = sorted(templates)
        self._templates = templates
        return templates

    def eval(self, item):
        if isinstance(item, six.integer_types):
            return item
        return constants.eval(item)

    def pretty(self, n, comment=True):
        if isinstance(n, (str, bytes, list, tuple, dict)):
            r = repr(n)
            if not comment:  # then it can be inside a comment!
                r = r.replace('*/', r'\x2a/')
            return r
        if not isinstance(n, six.integer_types):
            return n
        if isinstance(n, constants.Constant):
            if comment: return '%s /* %s */' % (n,self.pretty(int(n)))
            else:       return '%s (%s)'     % (n,self.pretty(int(n)))
        elif abs(n) < 10:
            return str(n)
        else:
            return hex(n)

    def okay(self, s, *a, **kw):
        if isinstance(s, six.integer_types):
            s = packing.pack(s, *a, **kw)
        return b'\0' not in s and b'\n' not in s

    from pwnlib.shellcraft import registers

# To prevent garbage collection
tether = sys.modules[__name__]

# Create the module structure
shellcraft = module(__name__, '')

class LazyImporter:
    def find_module(self, fullname, path=None):
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
