import pwn

# The current context
_context = {}

# Saved contexts
_saved = []

# Possible context values
possible_contexts = {
        'os': ['linux', 'freebsd'],
        'arch': ['i386', 'amd64', 'alpha', 'arm', 'thumb', 'cris', 'ia64', 'm68k', 'mips', 'powerpc', 'vax'],
        'network': ['ipv4', 'ipv6']
}

# Reverse dictionary
_reverse = {v:k for k, vs in possible_contexts.items() for v in vs}

def validate_context(k, v = None):
    '''Validates a context (key, value)-pair or a context value and dies if it is invalid.'''
    if v == None:
        v = k
        if v not in _reverse:
            pwn.die('Invalid context value: ' + str(v))
    else:
        if k not in possible_contexts:
            pwn.die('Invalid context key: ' + str(k))

        if v not in possible_contexts[k]:
            pwn.die('Invalid context value: ' + str(k) + '=' + str(v))

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
        validate_context(v)
        _context[_reverse[v]] = v

    for k, v in kwargs:
        validate_context(k, v)
        _context[k] = v

def with_context(**kwargs):
    '''Adds the current context to the kwargs, however kwarg-value can overrule the context.

    It also validates values in kwargs and adds (key, None) for non-existant keys.
    '''
    global _context

    for k in possible_contexts:
        if k in kwargs and kwargs[k] != None:
            validate_context(k, kwargs[k])
        elif k in _context:
            kwargs[k] = _context[k]
        else:
            kwargs[k] = None
    return kwargs

def need_context(f):
    @pwn.decoutils.ewraps(f)
    def wrapper(*args, **kwargs):
        with pwn.ExtraContext(kwargs) as c:
            return f(*args, **pwn.decoutils.kwargs_remover(f, c, possible_contexts.keys()))
    return wrapper

class ExtraContext:
    def __init__(self, kwargs):
        global _context
        self.old = _context.copy()
        self.new = with_context(**kwargs)

    def __enter__(self):
        global _context
        for k in possible_contexts.keys():
            _context[k] = self.new[k]
        return self.new

    def __exit__(self, exc_type, exc_value, traceback):
        global _context
        _context = self.old
