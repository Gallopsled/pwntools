def kwargs_remover(f, kwargs, check_list = None, clone = True):
    '''Removes all the keys from a kwargs-list, that a given function does not understand.

    The keys removed can optionally be restricted, so only keys from check_list are removed.'''
    import inspect

    if check_list == None: check_list = kwargs.keys()
    if clone: kwargs = kwargs.copy()
    if not f.func_code.co_flags & 8:
        args, varargs, keywords, defaults = getargspec(f)
        for c in set(check_list).intersection(kwargs.keys()):
            if c not in args:
                del kwargs[c]
    return kwargs

def getargs(co):
    """Get information about the arguments accepted by a code object.

    Three things are returned: (args, varargs, varkw), where 'args' is
    a list of argument names (possibly containing nested lists), and
    'varargs' and 'varkw' are the names of the * and ** arguments or None."""

    import dis

    CO_OPTIMIZED, CO_NEWLOCALS, CO_VARARGS, CO_VARKEYWORDS = 0x1, 0x2, 0x4, 0x8
    CO_NESTED, CO_GENERATOR, CO_NOFREE = 0x10, 0x20, 0x40
    nargs = co.co_argcount
    names = co.co_varnames
    args = list(names[:nargs])
    step = 0

    # The following acrobatics are for anonymous (tuple) arguments.
    for i in range(nargs):
        if args[i][:1] in ('', '.'):
            stack, remain, count = [], [], []
            while step < len(co.co_code):
                op = ord(co.co_code[step])
                step = step + 1
                if op >= dis.HAVE_ARGUMENT:
                    opname = dis.opname[op]
                    value = ord(co.co_code[step]) + ord(co.co_code[step+1])*256
                    step = step + 2
                    if opname in ('UNPACK_TUPLE', 'UNPACK_SEQUENCE'):
                        remain.append(value)
                        count.append(value)
                    elif opname == 'STORE_FAST':
                        stack.append(names[value])

                        # Special case for sublists of length 1: def foo((bar))
                        # doesn't generate the UNPACK_TUPLE bytecode, so if
                        # `remain` is empty here, we have such a sublist.
                        if not remain:
                            stack[0] = [stack[0]]
                            break
                        else:
                            remain[-1] = remain[-1] - 1
                            while remain[-1] == 0:
                                remain.pop()
                                size = count.pop()
                                stack[-size:] = [stack[-size:]]
                                if not remain: break
                                remain[-1] = remain[-1] - 1
                            if not remain: break
            args[i] = stack[0]

    varargs = None
    if co.co_flags & CO_VARARGS:
        varargs = co.co_varnames[nargs]
        nargs = nargs + 1
    varkw = None
    if co.co_flags & CO_VARKEYWORDS:
        varkw = co.co_varnames[nargs]
    return [args, varargs, varkw]

def getargspec(func):
    return getargs(func.func_code) + [func.func_defaults if func.func_defaults else []]

def method_signature(f):
    '''Returns the method signature for a function.'''
    spec = getargspec(f)

    args = []

    def simple_arg(a):
        if isinstance(a, list):
            return '(' + ', '.join(map(simple_arg, a)) + ')'
        return str(a)

    if spec[2] != None:
        args.append('**' + spec[2])
    if spec[1] != None:
        args.append('*' + spec[1])

    for n in range(len(spec[0])):
        cur = spec[0][len(spec[0])-n-1]

        if n < len(spec[3]):
            args.append(str(cur) + ' = ' + repr(spec[3][len(spec[3])-n-1]))
        else:
            args.append(simple_arg(cur))
    return f.func_name + '(' + ', '.join(reversed(args)) + ')'

def ewraps(wrapped):
    '''Extended version of functools.wraps.

    This version also adds the original method signature to the docstring.'''
    def deco(wrapper):
        import functools
        semi_fixed = functools.wraps(wrapped)(wrapper)
        if not wrapped.__dict__.get('signature_added', False):
            semi_fixed.__doc__ = method_signature(wrapped) + '\n\n' + (semi_fixed.__doc__ or '')
        semi_fixed.__dict__['signature_added'] = True
        return semi_fixed
    return deco

# Copied from Eli Bendersky's blog:
# http://eli.thegreenplace.net/2009/08/29/co-routines-as-an-alternative-to-state-machines/
def coroutine(func):
    def start(*args,**kwargs):
        cr = func(*args,**kwargs)
        cr.next()
        return cr
    return start


def memleaker(func):
    '''Create an information leak object.'''
    import leak
    return leak.MemLeak(func)
