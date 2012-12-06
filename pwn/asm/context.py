from pwn import concat
from shellcode import register_shellcode

_context = {}

_possible = {
        'os': ['linux', 'freebsd'],
        'arch': ['i386'],
        'network': ['ipv4', 'ipv6']
}

_reverse = {}

for _k,_vs in _possible.items():
    for _v in _vs:
        _reverse[_v] = _k

def _validate(k, v):
    if k not in _possible:
        die('Invalid context key: ' + str(k))

    if v not in _possible[k]:
        die('Invalid context value: ' + str(k) + '=' + str(v))

def _validate_v(value):
    if v not in _reverse:
        die('Invalid context value: ' + str(v))

def clear_context():
    global _context
    _context = {}

def context(*args, **kwargs):
    global _context
    for v in args:
        _validate_v(v)
        _context[_reverse[v]] = v

    for k, v in kwargs:
        _validate(k,v)
        _context[k] = v

def with_context(**kwargs):
    global _context

    for k in _possible:
        if k in kwargs:
            _validate(k, kwargs[k])
        elif k in _context:
            kwargs[k] = _context[k]
        else:
            kwargs[k] = None
    return kwargs


def shellcode_reqs(**supported_context):
    for k,vs in supported_context.items():
        if not isinstance(vs, list):
            vs = supported_context[k] = [vs]
        for v in vs:
            _validate(k, v)

    def deco(f):
        register_shellcode(f, supported_context)
        def wrapper(*args, **kwargs):
            kwargs = with_context(kwargs) 
           
            for k,vs in supported_context:
                if kwargs[k] not in vs:
                    die('Invalid context for ' + f.func_name + ': ' + k + '=' + kwargs[k] + ' is not supported')

            f(*args, **kwargs)
        return wrapper
    return deco

