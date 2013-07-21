import pwn

registered = {}

# For the benefit of the shellcodes
from pwn import *
from socket import htons

class AssemblerBlock:
    def __add__(self, other):
        return AssemblerContainer(self, other)

    def __radd__(self, other):
        return AssemblerContainer(other, self)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __flat__(self):
        return pwn.asm(self)

    def __len__(self):
        return len(pwn.flat(self))

class AssemblerBlob(AssemblerBlock):
    def __init__(self, blob, **kwargs):
        self.arch = kwargs.get('arch')
        self.os   = kwargs.get('os')
        self.blob = blob

        if not isinstance(blob, str):
            pwn.die('Trying to create an AssemblerBlob class, but the blob does not have type str.\nThe type is ' + str(type(blob)) + ' with the value:\n' + repr(blob)[:100])

    def __hash__(self):
        return hash((self.arch, self.os, self.blob))

    def __repr__(self):
        return 'AssemberBlob(%d)' % len(self)

class AssemblerText(AssemblerBlock):
    def __init__(self, text, **kwargs):
        self.arch = kwargs.get('arch')
        self.os   = kwargs.get('os')
        self.text = text

        if not isinstance(text, str):
            pwn.die('Trying to create an AssemblerText class, but the text does not have type str.\nThe type is ' + str(type(text)) + ' with the value:\n' + repr(text)[:100])

    def __hash__(self):
        return hash((self.arch, self.os, self.text))

    def __repr__(self):
        return 'AssemblerText(%s ...)' % self.text.strip().split('\n')[0][:20]


class AssemblerContainer(AssemblerBlock):
    def __init__(self, *blocks, **kwargs):
        self.arch   = kwargs.get('arch')
        self.os     = kwargs.get('os')
        self.blocks = []

        for b in pwn.concat_all(list(blocks)):
            if isinstance(b, AssemblerBlock):
                if self.os   == None: self.os   = b.os
                if self.arch == None: self.arch = b.arch

                if self.os != b.os and b.os != None:
                    pwn.die('Trying to combine assembler blocks with different os: ' + self.os + ' and ' + b.os)

                if self.arch != b.arch and b.arch != None:
                    pwn.die('Trying to combine assembler blocks with different archs: ' + self.arch + ' and ' + b.arch)

            if isinstance(b, AssemblerContainer):
                self.blocks.extend(b.blocks)
            elif isinstance(b, AssemblerBlock):
                self.blocks.append(b)
            elif isinstance(b, str):
                cast = kwargs.get('cast', 'blob')
                if cast == 'text':
                    self.blocks.append(AssemblerText(b, **kwargs))
                elif cast == 'blob':
                    self.blocks.append(AssemblerBlob(b, **kwargs))
                else:
                    pwn.die('Invalid cast for AssemblerContainer')
            else:
                pwn.die('Trying to force something of type ' + str(type(b)) + ' into an assembler block. Its value is:\n' + repr(b)[:100])

    def __hash__(self):
        return hash((self.arch, self.os, tuple(self.blocks)))

    def __repr__(self):
        return 'AssemblerContainer( %s )' % ', '.join(repr(b) for b in self.blocks)

def shellcode_wrapper(f, args, kwargs, avoider):
    kwargs = pwn.with_context(**kwargs)
    kwargs = pwn.decoutils.kwargs_remover(f, kwargs, pwn.possible_contexts.keys() + ['raw'])
    if avoider:
        return pwn.avoider(f)(*args, **kwargs)
    else:
        return f(*args, **kwargs)

def shellcode_reqs(blob = False, hidden = False, avoider = False, **supported_context):
    '''A decorator for shellcode functions, which registers the function
    with shellcraft and validates the context when the function is called.

    Example usage:
    @shellcode_reqs(os = ['linux', 'freebsd'], arch = 'i386')
    def sh(os = None):
        ...

    Notice that in this example the decorator will guarantee that os is
    either 'linux' or 'freebsd' before sh is called.
    '''

    for k, vs in supported_context.items():
        if not isinstance(vs, list):
            vs = supported_context[k] = [vs]
        for v in vs:
            pwn.validate_context(k, v)

    def deco(f):
        f.supported_context = supported_context
        @pwn.decoutils.ewraps(f)
        def wrapper(*args, **kwargs):
            with pwn.ExtraContext(kwargs) as kwargs:
                for k, vs in supported_context.items():
                    if kwargs[k] not in vs:
                        pwn.die('Invalid context for ' + f.func_name + ': ' + k + '=' + str(kwargs[k]) + ' is not supported')
                r = shellcode_wrapper(f, args, kwargs, avoider)
                if kwargs.get('raw') and isinstance(r, str):
                    return r.rstrip() + '\n'
                elif isinstance(r, AssemblerBlock):
                    return r
                elif isinstance(r, (tuple, list)):
                    kwargs['cast'] = 'blob' if blob else 'text'
                    return AssemblerContainer(*r, **kwargs)
                elif not blob:
                    return AssemblerText(r, **kwargs)
                else:
                    return AssemblerBlob(r, **kwargs)
        if not hidden:
            # we need the undecorated function to look up argcount and such
            registered[f.func_name] = (f, wrapper)
        return wrapper
    return deco

def arg_fixup(s):
    if not isinstance(s, str):
        return s
    try:
        import ast
        s2 = ast.literal_eval(s)
        if isinstance(s2, int):
            return s2
    except:
        pass
    try:
        s2 = pwn.clookup(s, eval = True)
        if isinstance(s2, list) and len(s2) == 1 and isinstance(s2[0], int):
            return s2[0]
    except:
        pass
    return s

def no_support(name, os, arch):
    pwn.bug("OS/arch combination (%s, %s) is not supported for %s" % (os, arch, name))

def indent_shellcode(shellcode):
    if isinstance(shellcode, list):
        shellcode = '\n'.join(shellcode)

    shellcode = [s.strip() for s in shellcode.split('\n')]
    shellcode = [('    ' + s if s and s[-1] != ':' else s) for s in shellcode]

    return '\n'.join(shellcode)
