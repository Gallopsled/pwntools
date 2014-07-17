from mako.lookup import TemplateLookup
from mako.parsetree import Tag, Text
from mako import ast
from os.path import dirname, abspath, join
from inspect import cleandoc

__all__ = ['make_function']

def relpath(path):
    curdir = dirname(abspath(__file__))
    return join(curdir, path)

def init_mako():
    global MAGIC, lookup, loaded

    if 'MAGIC' in globals():
        return

    MAGIC = '__pwn_docstring__'
    loaded = {}

    lookup = TemplateLookup(
        directories      = [relpath('templates')],
        module_directory = relpath('pycs')
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

            return '__doc__ = %s' % repr(docstring)

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

def make_function(key, directory):
    path     = join(directory, key + '.asm')
    template = lookup_template(path)

    import inspect
    args, varargs, keywords, defaults = inspect.getargspec(template.module.render_body)

    defaults = defaults or []

    if len(defaults) < len(args) and args[0] == 'context':
        args.pop(0)

    args_used = args[:]

    for n, default in enumerate(defaults, len(args) - len(defaults)):
        args[n] = '%s = %s' % (args[n], repr(default))

    if varargs:
        args.append('*' + varargs)
        args_used.append('*' + varargs)

    if keywords not in ['pageargs', None]:
        args.append('**' + keywords)
        args_used.append('**' + keywords)

    args      = ', '.join(args)
    args_used = ', '.join(args_used)

    # This is a slight hack to get the right signature for the function
    # It would be possible to simply create an (*args, **kwargs) wrapper,
    # but what would not have the right signature.
    # While we are at it, we insert the docstring too
    exec '''
def wrap(template):
    def %s(%s):
        %s
        s = template.render(%s).split('\\n')
        s = [l.rstrip() for l in s]
        while s and not s[-1]: s.pop()
        while s and not s[0]:  s.pop(0)
        return '\\n'.join(s)
    return %s
''' % (key, args, repr(cleandoc(template.module.__doc__)), args_used, key)

    # Setting _relpath is a slight hack only used to get better documentation
    res = wrap(template)
    res._relpath = path

    return res
