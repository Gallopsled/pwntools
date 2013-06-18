import pwn, sympy, re

def _is_sympy(o):
    '''Returns True, if o is a sympy object. Implemented using an ugly hack.'''
    return type(o).__module__.startswith('sympy.')

class name:
    def __init__(self, name):
        self.name = name

    def __rlshift__(self, other):
        if isinstance(other, Block):
            other.set_name(self.name)
            return other
        else:
            b = Block(other, name = self.name)
            if hasattr(other, 'wordsize'):
                b.wordsize = other.wordsize
            return b

def _sympy_eval(s):
    def fix(s):
        s_list = set([s])
        for n in range(100):
            s = s.subs(Block.symbols)
            if s.is_integer:
                break
            if s in s_list:
                break
            if repr(s) > 200:
                pwn.die('The expression "%s" is misbehaving' % repr(s))
            s_list.add(s)
        return s

    # Calculate a fixed point by replacing variables
    # Normally a single try should do it, but it can't hurt! :)
    s = fix(s)

    if not s.is_integer:
        # Perhaps somebody forgot to call update_all_symbols
        # Lets try it for them
        saved = Block.symbols
        update_all_symbols()

        # Lets see if the old symbols table contained anything
        # that is not available anymore. If that is the case,
        # then we back away and don't touch it
        ok = True
        for k in saved:
            if k not in Block.symbols:
                ok = False

        if not ok:
            Block.symbols = saved
        else:
            s = fix(s)

    # The will cause an exception in case of unresolved symbols
    return int(s)

class Block:
    _block_count = 0
    _roots = {}
    symbols = {}
    def __init__(self, content = None, wordsize = 4, name = None):
        self._content = []
        self.wordsize = wordsize
        self.parent = None
        if name:
            self.name = name
        else:
            self.name = "block%d" % Block._block_count
            Block._block_count += 1
        if self.name in Block._roots:
            pwn.die('A root block with the name "%s" already exicsts' % self.name)
        Block._roots[self.name] = self
        for o in pwn.concat_all([content]) if content != None else []:
            self._add(o)

    def set_name(self, name):
        if name == self.name:
            return

        if self.name in Block._roots:
            if name in Block._roots:
                pwn.die('A root block with the name "%s" already exicsts' % self.name)
            del Block._roots[self.name]
            Block._roots[name] = self
        self.name = name

    def __iadd__(self, other):
        for o in pwn.concat_all([other]):
            self._content.append(o)

        return self

    def _add(self, other):
        if isinstance(other, Block):
            other._set_parent(self)
        self._content.append(other)

    def _set_parent(self, other):
        if self.parent != None:
            pwn.die('Trying to set parent of "%s" to "%s", but parent was already "%s"' % (self, other, self.parent))
        self.parent = other
        del Block._roots[self.name]

    def __flat__(self):
        out = []

        def helper(o):
            if _is_sympy(o):
                return pwn.packs_little_endian[self.wordsize * 8](_sympy_eval(o))
            else:
                return pwn.flat(o, func = pwn.packs_little_endian[self.wordsize * 8])

        return ''.join(helper(o) for o in self._content)

    def __len__(self):
        res = 0

        for o in self._content:
            if isinstance(o, int) or _is_sympy(o):
                res += self.wordsize
            elif hasattr(o, '__len__'):
                res += len(o)
            else:
                res += len(pwn.flat(o))

        return res

    def __repr__(self):
        if re.match('^block[0-9]+$', self.name):
            res = '{ %s }'
        else:
            res = '%s { %%s } ' % self.name

        return res % ', '.join(repr(o) for o in self._content)

    def update_symbols(self, offset = 0, base = None):
        Block.symbols[self.name + '_offset_start'] = offset
        if base:
            Block.symbols[self.name + '_addr_start'] = base + offset

        for o in self._content:
            if isinstance(o, Block):
                offset = o.update_symbols(offset, base)
            elif isinstance(o, int) or _is_sympy(o):
                offset += self.wordsize
            elif hasattr(o, '__len__'):
                offset += len(o)
            else:
                offset += len(pwn.flat(o))
        if base:
            Block.symbols[self.name + '_addr_end'] = base + offset
        Block.symbols[self.name + '_offset_end']   = offset
        Block.symbols[self.name + '_size']  = Block.symbols[self.name + '_offset_end'] - Block.symbols[self.name + '_offset_start']

        return offset

def sizeof(n):
    return sympy.Symbol(n + '_size')

def addr(n):
    return sympy.Symbol(n + '_addr_start')

def addr_end(n):
    return sympy.Symbol(n + '_addr_end')

def offset(n):
    return sympy.Symbol(n + '_offset_start')

def offset_end(n):
    return sympy.Symbol(n + '_offset_end')

def update_all_symbols(known_bases = None):
    known_bases = known_bases or {}
    Block.symbols = {}
    for k, b in Block._roots.items():
        b.update_symbols(base = known_bases.get(k, None))
