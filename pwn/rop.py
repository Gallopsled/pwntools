import sys
from pwn import die, ELF, u8, p32, p64, randoms, findall
from collections import defaultdict

global _currently_loaded
_currently_loaded = None

class ROP:
    def __init__(self, file):
        global _currently_loaded
        if isinstance(file, ELF):
            self.elf = file
        else:
            self.elf = ELF(file)

        # bring addresses of sections, symbols, plt and got to this object
        self.sections = dict()
        for k, v in self.elf.sections.items():
            self.sections[k] = v['addr']
        self.symbols = dict()
        for k, v in self.elf.symbols.items():
            self.symbols[k] = v['addr']
        self.plt = self.elf.plt
        self.got = self.elf.got

        # promote to top-level
        g = globals()
        g['sections'] = self.sections
        g['symbols'] = self.symbols
        g['plt'] = self.plt
        g['got'] = self.got

        self._chain = []
        self._gadgets = {}
        self._load_gadgets()

        _currently_loaded = self

    def _load_gadgets(self):
        if self.elf.elfclass == 'ELF32':
            self._load32_popret()
            self._load32_migrate()

    def _exec_sections(self):
        for name, sec in self.elf.sections.items():
            if 'X' not in sec['flags']: continue
            data = self.elf.section(name)
            addr = sec['addr']
            yield (data, addr)

    def _load32_popret(self):
        addesp = '\x83\xc4'
        popr = map(chr, [0x58, 0x59, 0x5a, 0x5b, 0x5d, 0x5e, 0x5f])
        popa = '\x61'
        ret  = '\xc3'
        poprets = defaultdict(list)
        for data, addr in self._exec_sections():
            i = 0
            while True:
                i = data.find(ret, i)
                if i == -1: break
                s = [(i, 0)]
                while len(s) > 0:
                    off, size = s.pop(0)
                    gaddr = addr + off
                    poprets[size].append(gaddr)
                    if data[off - 1] in popr:
                        s.append((off - 1, size + 1))
                    if data[off - 1] == popa:
                        s.append((off - 1, size + 7))
                    if data[off - 3:off - 1] == addesp:
                        x = u8(data[off - 1])
                        if x % 4 == 0:
                            s.append((off - 3, size + x // 4))
                i += 1
        self._gadgets['popret'] = dict(poprets)

    def _load32_migrate(self):
        leave = '\xc9\xc3'
        popebp = '\x5d\xc3'
        ls = []
        ps = []
        for data, addr in self._exec_sections():
            idxs = findall(data, popebp)
            ls += map(lambda i: i + addr, idxs)
            idxs = findall(data, leave)
            ps += map(lambda i: i + addr, idxs)
        self._gadgets['leave'] = ls
        self._gadgets['popebp'] = ps

    def _resolve(self, x):
        if x is None or isinstance(x, int):
            return x
        for y in [self.plt, self.symbols, self.sections]:
            if x in y:
                return y[x]
        die('Could not resolve `%s\'' % x)

    def _pivot(self, args):
        pivot = None
        rets = self._gadgets['popret']
        for size in sorted(rets.keys()):
            if size >= len(args):
                pivot = rets[size][0]
                break
        if pivot is None:
            for i in findall(args, None):
                if i in rets.keys():
                    res = self._pivot(args[i + 1:])
                    if res is None: continue
                    pivot, size = res
                    args[i] = pivot
                    pivot = rets[i][0]
                    size += i + 1
                    break
        if pivot is not None:
            return (pivot, size)

    def migrate(self, addr):
        if self.elf.elfclass == 'ELF32':
            self._migrate32(addr)
        else:
            die('Only 32bit ELF supported')

    def _migrate32(self, addr):
        g = self._gadgets
        if len(g['popebp']) > 0 and len(g['leave']) > 0:
            self.call(g['popebp'][0], addr)
            self.call(g['leave'][0])
        else:
            die('Could not find set-EBP and leave gadgets needed to migrate chain')

    def word(self, word):
        self.call(word)

    def call(self, target, args = ()):
        '''Irrelevant arguments should be marked by a None'''
        target = self._resolve(target)
        if hasattr(args, '__iter__'):
            args = list(args)
        else:
            args = [args]
        args = map(self._resolve, args)
        self._chain.append((target, args))

    def generate(self):
        if self.elf.elfclass == 'ELF32':
            return self._generate32()
        else:
            die('Only 32bit ELF supported')

    def _generate32(self):
        out = []
        chain = self._chain
        garbage = lambda: randoms(4)
        p = p32
        def pargs(args):
            args = map(lambda a: garbage() if a is None else p(a), args)
            return args
        for i in range(len(chain)):
            target, args = chain[i]
            out.append(p(target))
            last = i == len(chain) - 1
            sndlast = i == len(chain) - 2
            if len(args) > 0:
                if last:
                    out.append(garbage())
                    args = pargs(args)
                elif sndlast and len(chain[i + 1][1]) == 0:
                    # the last target has no arguments, so go straight to it
                    out.append(p(chain[i + 1][0]))
                    out += pargs(args)
                    break
                else:
                    # find suitable popret
                    res = self._pivot(args)
                    if res is None:
                        die('Could not find gadget for pivoting %d arguments' % len(args))
                    pivot, size = res
                    args = pargs(args)
                    for _ in range(size - len(args)):
                        args.append(garbage())
                    out.append(p(pivot))
            out += args
        return ''.join(out)

    def __str__(self):
        return self.generate()

    def __repr__(self):
        return str(self)

    def __add__(x, y):
        return str(x) + str(y)

    def __radd__(x, y):
        return str(y) + str(x)

    def __getitem__(self, x):
        return self._resolve(x)

# alias
class load(ROP): pass

def _ensure_loaded():
    if _currently_loaded is None:
        die('No file loaded for ROP\'ing')

def call(*args):
    _ensure_loaded()
    _currently_loaded.call(*args)

def word(*args):
    _ensure_loaded()
    _currently_loaded.word(*args)

def migrate(*args):
    _ensure_loaded()
    _currently_loaded.migrate(*args)

def generate():
    _ensure_loaded()
    return _currently_loaded.generate()
