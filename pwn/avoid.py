import pwn
from pwn import decoutils as _decoutils

_default_avoid = set('\n\x00')
_all = set(chr(n) for n in range(256))
_avoid = _default_avoid

def _flatset(s):
    return set(pwn.flat(s, func=pwn.p8))

def set_avoid(s):
    global _avoid
    _avoid = _flatset(s)

def set_only(s):
    global _avoid
    _avoid = _all - _flatset(s)

def reset_avoid():
    global _avoid
    _avoid = _default_avoid

def reset_only():
    global _avoid
    _avoid = _default_avoid

def get_avoid():
    return sorted(_avoid)

def get_only():
    return sorted(_all - _avoid)

class avoid:
    def __init__(self, s, append = True):
        self.old = _avoid
        if append:
            self.new = _avoid.union(_flatset(s))
        else:
            self.new = _flatset(s)

    def __enter__(self):
        global _avoid
        _avoid = self.new

    def __exit__(self, exc_type, exc_value, traceback):
        global _avoid
        _avoid = self.old

class only:
    def __init__(self, s, append = True):
        self.old = _avoid
        if append:
            self.new = _avoid.union(_all - _flatset(s))
        else:
            self.new = _all - _flatset(s)

    def __enter__(self):
        global _avoid
        _avoid = self.new

    def __exit__(self, exc_type, exc_value, traceback):
        global _avoid
        _avoid = self.old

def avoider(f):
    @_decoutils.ewraps(f)
    def wrapper(*args, **kwargs):
        if 'avoid' in kwargs or 'only' in kwargs:
            avoided = _flatset(kwargs.get('avoid', ''))
            only = _flatset(kwargs.get('only', _all))
            kwargs = _decoutils.kwargs_remover(f, kwargs, check_list = ['avoid', 'only'])

            with avoid(avoided.union(_all - only), False):
                return f(*args, **kwargs)
        else:
            return f(*args, **kwargs)
    return wrapper
