import types, sys

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

class Local:
    def __init__ (self, tls):
        self.tls = tls
    def __enter__ (self):
        pass
    def __exit__ (self, *args):
        self.tls.pop()

class Module(types.ModuleType):
    def __init__ (self):
        # XXX: why are relative imports broken in the other functions?
        import log
        self._log = log
        self.__file__ = __file__
        self.__name__ = __name__
        self.__package__ = __package__
        self.__all__ = []
        self._template = template
        self._defaults = defaults
        self._ctx = {}
        self._ctxs = {}
        self._Local = Local

    def _error (self, s):
        log = self._log
        # the log module fetches the current log-level from this module, so we
        # need to be specific to not get recursive imports
        with log.loglevel(log.ERROR):
            log.error(s)

    def _update_ctx (self, ctx, kwargs):
        for k, v in kwargs.items():
            self._validate(k, v)
            ctx[k] = v

    def _validate_key (self, key):
        if key not in self._template:
            self._error('unknown context variable: %s' % key)

    def _validate (self, key, val):
        import types
        self._validate_key(key)
        valid = self._template[key]
        if isinstance(valid, types.TypeType):
            if not isinstance(val, valid):
                self._error('invalid context variable: %s (should be %s)' %
                      (val, valid)
                      )
        else:
            if not val in valid:
                self._error(
                    'invalid context variable: %s (should be one of %s)' %
                    (val, ', '.join(map(str, valid)))
                    )

    def __call__ (self, **kwargs):
        self._update_ctx(self._ctx, kwargs)

    def __setitem__ (self, key, val):
        self._validate(key, val)
        self._ctx[key] = val

    def __getitem__ (self, key):
        import threading
        self._validate_key(key)
        tid = threading.current_thread().ident
        tls = self._ctxs.get(tid, [])
        for ctx in reversed(tls):
            if key in ctx:
                return ctx[key]
        if key in self._ctx:
            return self._ctx[key]
        return self._defaults.get(key)

    def __delitem__ (self, key):
        self._validate_key(key)
        del self._ctx[key]

    def local (self, **kwargs):
        import threading
        ctx = {}
        self._update_ctx(ctx, kwargs)
        tid = threading.current_thread().ident
        if tid in self._ctxs:
            tls = self._ctxs[tid]
        else:
            tls = []
            self._ctxs[tid] = tls
        tls.append(ctx)
        return self._Local(tls)

    def __str__ (self):
        import threading
        tid = threading.current_thread().ident
        s = ''
        if tid in self._ctxs:
            s = 'Context for thread-%d:\n' % tid
        s = 'Context:\n'
        for k in self._template.keys():
            s += '  %s:\n    %s\n' % (k, self.__getitem__(k))
        return s[:-1]

if __name__ <> '__main__':
    sys.modules[__name__] = Module()
