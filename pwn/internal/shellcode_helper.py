import pwn
from pwn import decoutils

registered = {}

# For the benefit of the shellcodes
from pwn import *

class AssemblerBlock:
    def __add__(self, other):
        return AssemblerContainer(self, other)

    def __radd__(self, other):
        return AssemblerContainer(other, self)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

class AssemblerBlob(AssemblerBlock):
    def __init__(self, blob, **kwargs):
        self.arch = kwargs.get('arch')
        self.os   = kwargs.get('os')
        self.blob = blob

        if not isinstance(blob, str):
            pwn.die('Trying to create an AssemblerBlob class, but the blob does not have type str.\nThe type is ' + str(type(blob)) + ' with the value:\n' + repr(blob)[:100])

class AssemblerText(AssemblerBlock):
    def __init__(self, text, **kwargs):
        self.arch = kwargs.get('arch')
        self.os   = kwargs.get('os')
        self.text = text

        if not isinstance(text, str):
            pwn.die('Trying to create an AssemblerText class, but the text does not have type str.\nThe type is ' + str(type(text)) + ' with the value:\n' + repr(text)[:100])

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
                    die('Invalid cast for AssemblerContainer')
            else:
                pwn.die('Trying to force something of type ' + str(type(b)) + ' into an assembler block. Its value is:\n' + repr(b)[:100])

def shellcode_wrapper(f, args, kwargs, avoider):
    kwargs = pwn.with_context(**kwargs)
    if avoider:
        return pwn.avoider(f)(*args, **decoutils.kwargs_remover(f, kwargs, pwn.possible_contexts.keys()))
    else:
        return f(*args, **decoutils.kwargs_remover(f, kwargs, pwn.possible_contexts.keys()))

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
        if k in pwn.possible_contexts:
            # We support it all (yay), so don't say so explicitly
            if set(vs) == set(pwn.possible_contexts[k]):
                del supported_context[k]
        if not isinstance(vs, list):
            vs = supported_context[k] = [vs]
        for v in vs:
            pwn.validate_context(k, v)

    def deco(f):
        f.supported_context = supported_context
        @decoutils.ewraps(f)
        def wrapper(*args, **kwargs):
            with pwn.ExtraContext(kwargs) as kwargs:
                for k, vs in supported_context.items():
                    if kwargs[k] not in vs:
                        pwn.die('Invalid context for ' + f.func_name + ': ' + k + '=' + str(kwargs[k]) + ' is not supported')
                r = shellcode_wrapper(f, args, kwargs, avoider)
                if isinstance(r, AssemblerBlock):
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

