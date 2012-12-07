from shellcode import register_shellcode
from pwn import die

# The current context
_context = {}

# Possible context values
_possible = {
        'os': ['linux', 'freebsd'],
        'arch': ['i386'],
        'network': ['ipv4', 'ipv6']
}

# Reverse dictionary
_reverse = {v:k for k,vs in _possible.items() for v in vs}

def _validate(k, v):
    '''Validates a context (key, value)-pair and dies if it is invalid.'''
    if k not in _possible:
        die('Invalid context key: ' + str(k))

    if v not in _possible[k]:
        die('Invalid context value: ' + str(k) + '=' + str(v))

def _validate_v(value):
    '''Validates a context value and dies if it is invalid.'''
    if v not in _reverse:
        die('Invalid context value: ' + str(v))

def clear_context():
    '''Clears the current context.'''
    global _context
    _context = {}

def context(*args, **kwargs):
    '''Adds/overwrites the current context.

    Typical usage:
    context('i386', 'linux', 'ipv4')
    '''
    global _context
    for v in args:
        _validate_v(v)
        _context[_reverse[v]] = v

    for k, v in kwargs:
        _validate(k,v)
        _context[k] = v

def with_context(**kwargs):
    '''Adds the current context to the kwargs, however kwarg-value can overrule the context.

    It also validates values in kwargs and adds (key, None) for non-existant keys.
    '''
    global _context

    for k in _possible:
        if k in kwargs and kwargs[k] != None:
            _validate(k, kwargs[k])
        elif k in _context:
            kwargs[k] = _context[k]
        else:
            kwargs[k] = None
    return kwargs


def shellcode_reqs(**supported_context):
    '''A decorator for shellcode functions, which registers the function
    with shellcraft and validates the context when the function is called.
    
    Example usage:
    @shellcode_reqs(os = ['linux', 'freebsd'], arch = 'i386')
    def sh(os = None):
        ...

    Notice that in this example the decorator will guarantee that os is
    either 'linux' or 'freebsd' before sh is called.
    '''
    for k,vs in supported_context.items():
        if not isinstance(vs, list):
            vs = supported_context[k] = [vs]
        for v in vs:
            _validate(k, v)

    def deco(f):
        register_shellcode(f, supported_context)
        def wrapper(*args, **kwargs):
            kwargs = with_context(**kwargs) 
           
            for k,vs in supported_context.items():
                if kwargs[k] not in vs:
                    die('Invalid context for ' + f.func_name + ': ' + k + '=' + str(kwargs[k]) + ' is not supported')

            return f(*args, **kwargs)
        return wrapper
    return deco

