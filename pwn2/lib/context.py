import types, sys, threading

# If these are updated, remember to update the documentation
possible = {
    'arch':
       ('i386', 'amd64', 'arm', 'armel', 'armeb', 'ppc'),

    'net':
       ('ipv4', 'ipv6'),

    'os':
       ('linux', 'freebsd'),

    'target_binary':
       types.StringType,

    'target_host':
       types.StringType,

    'target_port':
       types.IntType,

    'endianness':
       ('big', 'little'),

    'word_size':
       types.IntType,

    'log_level':
       ('debug', 'info', 'error', 'silent'),
}

defaults = {
    'endianness': 'little'
}

def validate(args):
    out = {}

    for key, value in args.items():
        if key not in possible:
            raise AttributeError('Cannot access context-key %s' % key)

        verify = possible[key]

        if isinstance(verify, types.FunctionType):
            out.update(verify(key, value))
        else:
            # You can always set it to None
            if value != None:
                if isinstance(verify, types.TypeType):
                    if type(value) != verify:
                        raise AttributeError('Cannot set context-key %s to %s, it is not of type %s' % (key, repr(value), verify.__name__))

                elif not value in verify:
                    raise AttributeError('Cannot set context-key %s to %s, it is not in the list of allowed values' % (key, repr(value)))
            out[key] = value
    return out


def validate_one(key, value = None):
    return validate({key: value})


def thread_id():
    return threading.current_thread().ident


class Local(object):
    def __init__(self, args):
        self.args = args

    def __enter__(self):
        self.saved = context._get_thread_ctx().copy()
        context._get_thread_ctx().update(self.args)

    def __exit__(self, *args):
        context._set_thread_ctx(self.saved)


class DefaultsModule(types.ModuleType):
    '''The module for the global defaults for the context variables.'''

    def __init__(self):
        super(DefaultsModule, self).__init__(__name__ + '.defaults')
        sys.modules[self.__name__] = self
        self.__dict__.update({
            '__all__'     : [],
            '__doc__'     : DefaultsModule.__doc__,
            '__file__'    : __file__,
            '__package__' : __package__,
            '_possible'   : possible
        })

        self.__dict__.update(defaults)

    def __call__(self, **kwargs):
        self.__dict__.update(validate(kwargs))

    def __getattr__(self, key):
        validate_one(key)
        return self.__dict__.get(key)

    def __setattr__(self, key, val):
        self.__dict__.update(validate_one(key, val))

    def __dir__(self):
        res = set(self.__dict__.keys())
        res = res.union(possible.keys())
        return sorted(res)


class MainModule(types.ModuleType):
    '''The module for thread-local context variables.'''

    def __init__(self):
        super(MainModule, self).__init__(__name__)
        sys.modules[self.__name__] = self
        self.__dict__.update({
            '__all__'     : ['defaults', 'local', 'reset_local'],
            '__doc__'     : MainModule.__doc__,
            '__file__'    : __file__,
            '__package__' : __package__,
            'defaults'    : DefaultsModule(),
            '_possible'   : possible,
            '_ctxs'       : {}
        })

    def __call__(self, **kwargs):
        for k, v in kwargs.items():
            self.__setattr__(k, v)

    def __getattr__(self, key):
        validate_one(key)
        if key in self._get_thread_ctx():
            return self._get_thread_ctx()[key]
        return self.defaults.__getattr__(key)

    def __setattr__(self, key, val):
        self._get_thread_ctx().update(validate_one(key, val))

    def __dir__(self):
        res = set(self.__dict__.keys())
        res = res.union(possible.keys())
        return sorted(res)

    def _get_thread_ctx(self):
        return self._ctxs.setdefault(thread_id(), {})

    def _set_thread_ctx(self, ctx):
        self._ctxs[thread_id()] = ctx

    def local(self, **kwargs):
        '''Return a `context manager <https://docs.python.org/2/reference/compound_stmts.html#the-with-statement>`_.

        Upon entering this context manager will save current thread-local
        environment and create a new identical one. On exit, it will restore
        the original environment.

        As a convenience, it also accepts a number of kwarg-style arguments for
        settings variables in the newly created environment.

        Example:

        .. doctest:: text_context_local

           >>> print context.arch
           None
           >>> with context.local(arch = 'i386'):
           ...     print context.arch
           ...     context.arch = 'arm'
           ...     print context.arch
           i386
           arm
           >>> print context.arch
           None

Return an object to be used as the argument for a ``with`` statement.'''

        return Local(validate(kwargs))

    def reset_local(self):
        '''Completely clears the current thread-local context, thus making the
        value from :mod:`pwn2.lib.context.defaults` "shine through".'''
        self._ctxs[thread_id()] = {}


if __name__ <> '__main__':
    # prevent this scope from being GC'ed
    tether = sys.modules[__name__]
    context = MainModule()
