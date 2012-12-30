import functools, inspect

def kwargs_remover(f, kwargs, check_list = None, clone = True):
    '''Removes all the keys from a kwargs-list, that a given function does not understand.

    The keys removed can optionally be restricted, so only keys from check_list are removed.'''

    if check_list == None: check_list = kwargs.keys()
    if clone: kwargs = kwargs.copy()
    if not f.func_code.co_flags & 8:
        for c in set(check_list).intersection(kwargs.keys()):
            if c not in f.func_code.co_varnames:
                del kwargs[c]
    return kwargs

def method_signature(f):
    '''Returns the method signature for a function.'''
    spec = list(inspect.getargspec(f))
    if spec[3] == None: spec[3] = []

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
        semi_fixed = functools.wraps(wrapped)(wrapper)
        if not wrapped.__dict__.get('signature_added', False):
            semi_fixed.__doc__ = method_signature(wrapped) + '\n\n' + (semi_fixed.__doc__ or '')
        semi_fixed.__dict__['signature_added'] = True
        return semi_fixed
    return deco
