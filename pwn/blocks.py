import pwn

class _Block:
    _block_count = 0

    def _setup_lengths(self):
        self.length8  = _Length(self, pwn.p8)
        self.length16 = _Length(self, pwn.p16)
        self.length32 = _Length(self, pwn.p32)
        self.length64 = _Length(self, pwn.p64)
        self.length64 = _Length(self, pwn.p64)

        self.length8b  = _Length(self, pwn.p8b)
        self.length16b = _Length(self, pwn.p16b)
        self.length32b = _Length(self, pwn.p32b)
        self.length64b = _Length(self, pwn.p64b)
        self.length64b = _Length(self, pwn.p64b)

        self.length   = _Length(self)

    def __init__(self, func = pwn.p32):
        self._entries = []
        self._func = func
        self.id = _Block._block_count
        _Block._block_count += 1
        self._setup_lengths()

    def __iadd__(self, other):
        for o in pwn.concat_all([other]):
            if isinstance(o, _Later):
                o._block = self
            self._entries.append(o)
        return self

    def _get_func(self, o):
        if hasattr(o, '_func') and o._func:
            return o._func
        return self._func

    def __flat__(self):
        out = ''

        for e in self._entries:
            if isinstance(e, _Expr):
                out += self._get_func(e)(e.force())
            else:
                out += pwn.flat(e, func=self._func)
        return out

    def __len__(self):
        l = 0

        for e in self._entries:
            if isinstance(e, int):
                l += len(self._func(0))
            elif isinstance(e, _Expr):
                l += len(self._get_func(e)(0))
            else:
                l += len(e)
        return l

    def _repr_helper(self, contained):
        if self in contained:
            return "Block%d" % self.id

        contained = contained.union({self})
        out = []

        for o in self._entries:
            if isinstance(o, _Block):
                out.append(o._repr_helper(contained))
            elif isinstance(o, _Length):
                out.append("%s(%s)" % (o._name(), o._block._repr_helper(contained)))
            else:
                out.append(repr(o))

        return "Block%d { %s }" % (self.id, ", ".join(out))

    def __repr__(self):
        return self._repr_helper(set())

class _Expr:
    def __init__(self, expr, func = None):
        self._expr = expr
        self._func = func

    def force(self):
        return self._expr()

    def __repr__(self):
        return "*expression[%s]*" % pwn.pack_size(self._func)

class _Length(_Expr):
    def __init__(self, block, func = None):
        self._expr = lambda: len(block)
        self._block = block
        self._func = func

    def _name(self):
        return "len[%s]" % pwn.pack_size(self._func)

    def __repr__(self):
        return "%s(%s)" % (self._name(), repr(self._block))

class _Later(_Expr):
    def __init__(self, attr, func = None):
        self._attr = attr
        self._func = func

    def _expr(self):
        if not hasattr(self, "_block"):
            raise Exception("You have not yet added the later expression to a block")
        if not hasattr(self._block, self._attr):
            raise Exception("You have not yet set the '%s' attribute!" % self._attr)
        return getattr(self._block, self._attr)

    def __repr__(self):
        return "%s[%s]" % (self._attr, pwn.pack_size(self._func))

def block(func = pwn.p32):
    return _Block(func)

def expr(expr, func = None):
    return _Expr(expr, func)

def later(attr, func = None):
    return _Later(attr, func)
