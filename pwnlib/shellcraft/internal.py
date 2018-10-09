from __future__ import absolute_import
from __future__ import division

import os
from collections import defaultdict

from pwnlib.context import context

__all__ = ['make_function']

loaded = {}
lookup = None
def init_mako():
    global lookup, render_global
    from mako.lookup import TemplateLookup
    from mako.parsetree import Tag, Text
    from mako import ast
    import threading

    if lookup != None:
        return

    class IsInsideManager:
        def __init__(self, parent):
            self.parent = parent
        def __enter__(self):
            self.oldval = self.parent.is_inside
            self.parent.is_inside = True
            return self.oldval
        def __exit__(self, *args):
            self.parent.is_inside = self.oldval

    class IsInside(threading.local):
        is_inside = False

        def go_inside(self):
            return IsInsideManager(self)

    render_global = IsInside()

    cache  = context.cache_dir
    if cache:
        cache = os.path.join(cache, 'mako')

    curdir = os.path.dirname(os.path.abspath(__file__))
    lookup = TemplateLookup(
        directories      = [os.path.join(curdir, 'templates')],
        module_directory = cache
    )

    # The purpose of this definition is to create a new Tag.
    # The Tag has a metaclass, which saves this definition even
    # though to do not use it here.
    class pwn_docstring(Tag):
        __keyword__ = 'docstring'

        def __init__(self, *args, **kwargs):
            super(pwn_docstring, self).__init__('docstring', (), (), (), (), **kwargs)
            self.ismodule = True

        @property
        def text(self):
            children = self.get_children()
            if len(children) != 1 or not isinstance(children[0], Text):
                raise Exception("docstring tag only supports text")

            docstring = children[0].content

            return '__doc__ = %r' % docstring

        @property
        def code(self):
            return ast.PythonCode(self.text)

        def accept_visitor(self, visitor):
            method = getattr(visitor, "visitCode", lambda x: x)
            method(self)

def lookup_template(filename):
    init_mako()

    if filename not in loaded:
        loaded[filename] = lookup.get_template(filename)

    return loaded[filename]

def get_context_from_dirpath(directory):
    """
    >>> get_context_from_dirpath('common')
    {}
    >>> get_context_from_dirpath('i386')
    {'arch': 'i386'}
    >>> get_context_from_dirpath('amd64/linux') == {'arch': 'amd64', 'os': 'linux'}
    True
    """
    parts = directory.split(os.path.sep)

    arch = osys = None

    if len(parts) > 0:
        arch = parts[0]
    if len(parts) > 1:
        osys = parts[1]

    if osys == 'common':
        osys = None
    if arch == 'common':
        arch = None

    return {'os': osys, 'arch': arch}

def make_function(funcname, filename, directory):
    import inspect
    path       = os.path.join(directory, filename)
    template   = lookup_template(path)

    args, varargs, keywords, defaults = inspect.getargspec(template.module.render_body)

    defaults = defaults or []

    if len(defaults) < len(args) and args[0] == 'context':
        args.pop(0)

    args_used = args[:]

    for n, default in enumerate(defaults, len(args) - len(defaults)):
        args[n] = '%s = %r' % (args[n], default)

    if varargs:
        args.append('*' + varargs)
        args_used.append('*' + varargs)

    if keywords not in ['pageargs', None]:
        args.append('**' + keywords)
        args_used.append('**' + keywords)

    docstring = inspect.cleandoc(template.module.__doc__ or '')
    args      = ', '.join(args)
    args_used = ', '.join(args_used)
    local_ctx = get_context_from_dirpath(directory)

    # This is a slight hack to get the right signature for the function
    # It would be possible to simply create an (*args, **kwargs) wrapper,
    # but what would not have the right signature.
    # While we are at it, we insert the docstring too
    T = '''
def wrap(template, render_global):
    import pwnlib
    def %(funcname)s(%(args)s):
        %(docstring)r
        with render_global.go_inside() as was_inside:
            with pwnlib.context.context.local(**%(local_ctx)s):
                lines = template.render(%(args_used)s).split('\\n')
        for i in range(len(lines)):
            line = lines[i]
            def islabelchar(c):
                return c.isalnum() or c == '.' or c == '_'
            if ':' in line and islabelchar(line.lstrip()[0]):
                line = line.lstrip()
            elif line.startswith(' '):
                 line = '    ' + line.lstrip()
            lines[i] = line
        while lines and not lines[-1]: lines.pop()
        while lines and not lines[0]:  lines.pop(0)
        s = '\\n'.join(lines)
        while '\\n\\n\\n' in s:
            s = s.replace('\\n\\n\\n', '\\n\\n')

        if was_inside:
            return s
        else:
            return s + '\\n'
    return %(funcname)s
''' % locals()

    g = {}
    exec(T, g, g)
    wrap = g['wrap']

    # Setting _relpath is a slight hack only used to get better documentation
    res = wrap(template, render_global)
    res._relpath = path
    res.__module__ = 'pwnlib.shellcraft.' + os.path.dirname(path).replace('/','.')

    import sys, inspect, functools

    @functools.wraps(res)
    def function(*a):
        return sys.modules[res.__module__].function(res.__name__, res, *a)
    @functools.wraps(res)
    def call(*a):
        return sys.modules[res.__module__].call(res.__name__, *a)

    res.function = function
    res.call     = call

    return res
