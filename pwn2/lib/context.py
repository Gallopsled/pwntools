import types, sys, log, threading

template = {
    'arch':
       ('i386', 'amd64', 'arm', 'armel', 'armeb', 'ppc'),

    'net':
       ('ipv4', 'ipv6'),

    'os':
       ('linux', 'freebsd'),

    'target':
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

}

def error (s):
    # the log module fetches the current log-level from this module, so we
    # need to be specific to not get recursive imports
    with log.loglevel(log.ERROR):
        log.error(s)

def update_ctx (ctx, kwargs):
    for k, v in kwargs.items():
        validate(k, v)
        ctx[k] = v

def validate_key (key):
    if key not in template:
        error('unknown context variable: %s' % key)

def validate (key, val):
    validate_key(key)
    valid = template[key]
    if isinstance(valid, types.TypeType):
        if not isinstance(val, valid):
            error('invalid context variable: %s (should be %s)' %
                  (val, valid)
                  )
    else:
        if not val in valid:
            error('invalid context variable: %s (should be one of %s)' %
                  (val, ', '.join(map(str, valid)))
                  )

class Local:
    def __init__ (self, tls):
        self.tls = tls
    def __enter__ (self):
        pass
    def __exit__ (self, *args):
        self.tls.pop()

class Module(types.ModuleType):
    def __init__ (self):
        types.ModuleType.__init__(self, __name__)
        self.__dict__['__file__'] = __file__
        self.__dict__['__package__'] = __package__
        self.__dict__['__all__'] = []
        self.__dict__['_ctx'] = {}
        self.__dict__['_ctxs'] = {}

    def __call__ (self, **kwargs):
        update_ctx(self._ctx, kwargs)

    def __setattr__ (self, key, val):
        validate(key, val)
        self._ctx[key] = val

    def __getattr__ (self, key):
        validate_key(key)
        tid = threading.current_thread().ident
        tls = self._ctxs.get(tid, [])
        for ctx in reversed(tls):
            if key in ctx:
                return ctx[key]
        if key in self._ctx:
            return self._ctx[key]
        return defaults.get(key)

    def __delattr__ (self, key):
        validate_key(key)
        del self._ctx[key]

    def local (self, **kwargs):
        '''Set context local to current with-block in current thread'''
        ctx = {}
        update_ctx(ctx, kwargs)
        tid = threading.current_thread().ident
        if tid in self._ctxs:
            tls = self._ctxs[tid]
        else:
            tls = []
            self._ctxs[tid] = tls
        tls.append(ctx)
        return Local(tls)

    def dict (self):
        '''Return the current context as a dictionary'''
        return {k: self.__getattr__(k) for k in template.keys()}

    def __str__ (self):
        tid = threading.current_thread().ident
        s = ''
        if tid in self._ctxs:
            s = 'Context for thread-%d:\n' % tid
        s = 'Context:\n'
        for k in template.keys():
            s += '  %s:\n    %s\n' % (k, self.__getattr__(k))
        return s[:-1]

if __name__ <> '__main__':
    # prevent this scope from being GC'ed
    tether = sys.modules[__name__]
    sys.modules[__name__] = Module()
