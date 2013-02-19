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

    def __init__(self, packer = pwn.p32):
        self._entries = []
        self._packer = packer
        self.id = _Block._block_count
        _Block._block_count += 1
        self._setup_lengths()

    def __iadd__(self, other):
        self._entries.extend(pwn.concat_all([other]))
        return self

    def __flat__(self):
        out = ''

        for e in self._entries:
            if isinstance(e, _Expr):
                if e._packer:
                    out += e._packer(e.force())
                else:
                    out += self._packer(e.force())
            else:
                out += pwn.flat(e, func=self._packer)
        return out

    def __len__(self):
        l = 0

        for e in self._entries:
            if isinstance(e, int):
                l += len(self._packer(0))
            elif isinstance(e, _Expr):
                if e._packer:
                    l += len(e._packer(0))
                else:
                    l += len(self._packer(0))
            else:
                l += len(e)
        return l

    def __str__(self):
        return self.__flat__()

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

        return "Block%d [ %s ]" % (self.id, ", ".join(out))

    def __repr__(self):
        return self._repr_helper(set())

class _Expr:
    def __init__(self, expr, packer = None):
        self._expr = expr
        self._packer = packer

    def force(self):
        return self._expr()


    def __repr__(self):
        if self._packer == pwn.p8:   return "*expression8*"
        if self._packer == pwn.p16:  return "*expression16*"
        if self._packer == pwn.p32:  return "*expression32*"
        if self._packer == pwn.p64:  return "*expression64*"

        if self._packer == pwn.p8b:  return "*expression8b*"
        if self._packer == pwn.p16b: return "*expression16b*"
        if self._packer == pwn.p32b: return "*expression32b*"
        if self._packer == pwn.p64b: return "*expression64b*"

        return "*expression*"

class _Length(_Expr):
    def __init__(self, block, packer = None):
        self._expr = lambda: len(block)
        self._block = block
        self._packer = packer

    def _name(self):
        if self._packer == pwn.p8:   return "len8"
        if self._packer == pwn.p16:  return "len16"
        if self._packer == pwn.p32:  return "len32"
        if self._packer == pwn.p64:  return "len64"

        if self._packer == pwn.p8b:  return "len8b"
        if self._packer == pwn.p16b: return "len16b"
        if self._packer == pwn.p32b: return "len32b"
        if self._packer == pwn.p64b: return "len64b"

        return "len"

    def __repr__(self):
        return "%s(%s)" % (self._name, repr(self._block))

def block(packer = pwn.p32):
    return _Block(packer)

def expr(expr, packer = None):
    return _Expr(expr, packer)
