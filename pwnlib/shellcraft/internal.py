from mako.lookup import TemplateLookup
from mako.parsetree import Tag, Text
from mako import ast
from os.path import dirname, abspath, join
import pwn2.lib.internal

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

    import pwn2.lib.shellcraft
    imports = ', '.join(pwn2.lib.shellcraft._submodules.keys())

    lookup = TemplateLookup(
        directories      = [relpath('templates')],
        module_directory = relpath('pycs'),
        imports          = [
            'from pwn2.lib.shellcraft import ' + imports,
            'from pwn2.lib import shellcraft',
            'import pwn2.lib'
        ]
    )

    class pwn_docstring(Tag):
        __keyword__ = 'docstring'

        def __init__(self, *args, **kwargs):
            super(pwn_docstring, self).__init__('docstring', (), (), (), (), **kwargs)
            self.ismodule = False

        @property
        def text(self):
            children = self.get_children()
            if len(children) != 1 or not isinstance(children[0], Text):
                raise Exception("docstring tag only supports text")

            docstring = children[0].content

            return '%s = %s' % (MAGIC, repr(MAGIC + docstring))

        @property
        def code(self):
            return ast.PythonCode(self.text)

        def accept_visitor(self, visitor):
            method = getattr(visitor, "visitCode", lambda x: x)
            method(self)

def get_pwn_docstring(func):
    for c in func.func_code.co_consts:
        if isinstance(c, (str, unicode)) and c.startswith(MAGIC):
            return pwn2.lib.internal.docstring_trim(c[len(MAGIC):]) + '\n\nReturns:\n    str: The desired code.'
    return ''

def lookup_template(filename):
    init_mako()

    if filename not in loaded:
        loaded[filename] = lookup.get_template(filename)

    return loaded[filename]

def make_function(key, directory, filename):
    path = join(directory, filename)
    template = lookup_template(path)

    if key + '.asm' == filename:
        renderer = template.render
        inner    = template.module.render_body
    else:
        renderer = template.get_def(key).render
        inner = getattr(template.module, 'render_' + key)

    import inspect
    args, varargs, keywords, defaults = inspect.getargspec(inner)

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

    exec '''
def wrap(renderer):
    def %s(%s):
        %s
        s = renderer(%s).split('\\n')
        s = [l.rstrip() for l in s]
        while s and not s[-1]: s.pop()
        while s and not s[0]:  s.pop(0)
        return '\\n'.join(s)
    return %s
''' % (key, args, repr(get_pwn_docstring(inner)), args_used, key)

    return wrap(renderer)

