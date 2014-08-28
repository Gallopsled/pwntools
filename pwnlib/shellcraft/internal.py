import os

__all__ = ['make_function']

loaded = {}
lookup = None
def init_mako():
    global lookup
    from mako.lookup import TemplateLookup
    from mako.parsetree import Tag, Text
    from mako import ast

    if lookup != None:
        return

    curdir = os.path.dirname(os.path.abspath(__file__))
    lookup = TemplateLookup(
        directories      = [os.path.join(curdir, 'templates')],
        module_directory = os.path.expanduser('~/.pwntools-cache/mako')
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

    args      = ', '.join(args)
    args_used = ', '.join(args_used)

    # This is a slight hack to get the right signature for the function
    # It would be possible to simply create an (*args, **kwargs) wrapper,
    # but what would not have the right signature.
    # While we are at it, we insert the docstring too
    exec '''
def wrap(template):
    def %s(%s):
        %r
        lines = template.render(%s).split('\\n')
        for i in xrange(len(lines)):
            line = lines[i]
            line = line.rstrip()
            if line.endswith(':'):
                line = line.lstrip()
            elif line.startswith('    '):
                 line = '    ' + line.lstrip()
            lines[i] = line
        while lines and not lines[-1]: lines.pop()
        while lines and not lines[0]:  lines.pop(0)
        s = '\\n'.join(lines)
        while '\\n\\n\\n' in s:
            s = s.replace('\\n\\n\\n', '\\n\\n')
        return s
    return %s
''' % (funcname, args, inspect.cleandoc(template.module.__doc__ or ''), args_used, funcname)

    # Setting _relpath is a slight hack only used to get better documentation
    res = wrap(template)
    res._relpath = path

    return res
