import sys, random, os, subprocess, pwn
from pwn import die, elf, ELF, u8, p32, p64, pint, findall, group, tuplify, flat
from collections import defaultdict

class ROP:
    def __init__(self, file, garbage = 0xdeadbeef):
        global _currently_loaded
        if isinstance(file, ELF):
            self.elf = file
        else:
            self.elf = ELF(file)

        self.garbage = tuplify(garbage)

        # bring segments, sections, symbols, plt and got to this object
        self.segments = self.elf.segments
        self.sections = dict()
        for k, v in self.elf.sections.items():
            self.sections[k] = v['addr']
        self.symbols = dict()
        for k, v in self.elf.symbols.items():
            self.symbols[k] = v['addr']
        self.plt = self.elf.plt
        self.got = self.elf.got

        self._chain = []
        self._gadgets = {}
        self._load_addr = None
        self._next_load_addr = None
        self._load_gadgets()

    def extra_libs(self, libs):
        self.elf.extra_libs(libs)

    def load_library(self, file, addr, relative_to = None):
        syms = {}

        if not os.path.exists(file):
            if file in self.elf.libs:
                file = self.elf.libs[file]
            else:
                die('Could not load library, file %s does not exist.' % file)

        for k, v in elf.symbols(file).items():
            if '@@' in k:
                k = k[:k.find('@@')]
            syms[k] = v
        offset = addr
        if relative_to:
            if relative_to not in syms:
                die('Could not load library relative to "%s" -- no such symbol', relative_to)
            offset -= syms[relative_to]['addr']
        for k, v in syms.items():
            self.symbols[k] = v['addr'] + offset

    def add_symbol(self, symbol, addr):
        self.symbols[symbol] = addr

    def set_load_addr(self, addr):
        self._load_addr = addr

    def _load_gadgets(self):
        if self.elf.elfclass == 'ELF32':
            self._load32_popret()
            self._load32_migrate()

    def _load32_popret(self):
        addesp = '\x83\xc4'
        popr = map(chr, [0x58, 0x59, 0x5a, 0x5b, 0x5d, 0x5e, 0x5f])
        popa = '\x61'
        ret  = '\xc3'
        poprets = defaultdict(list)
        for data, addr in self.elf.executable_segments():
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
        for data, addr in self.elf.executable_segments():
            idxs = findall(data, leave)
            ls += map(lambda i: i + addr, idxs)
            idxs = findall(data, popebp)
            ps += map(lambda i: i + addr, idxs)
        self._gadgets['leave'] = ls
        self._gadgets['popebp'] = ps

    def _resolve(self, x):
        if x is None or isinstance(x, int):
            return x
        for y in [self.symbols, self.plt, self.sections]:
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

    def migrate(self, sp, bp = None):
        self._next_load_addr = sp
        self._chain.append(('migrate', (sp, bp)))
        return self

    def set_frame(self, addr):
        if self.elf.elfclass == 'ELF32':
            self._set_frame32(addr)
        else:
            die('Only 32bit ELF supported')

    def _set_frame32(self, addr):
        gs = self._gadgets['popebp']
        if gs <> []:
            self.raw(gs[0], addr)
        else:
            die('Could not find set-EBP gadget')

    def call(self, target, args = (), pivot = None):
        '''Irrelevant arguments should be marked by a None'''
        target = self._resolve(target)
        self._chain.append(('call', (target, pivot, tuplify(args))))
        return self

    def raw(self, *words):
        self._chain.append(('raw', words))
        return self

    def flush(self, loaded_at = None):
        if loaded_at is not None:
            self._load_addr = loaded_at
        if self.elf.elfclass == 'ELF32':
            return self._generate32()
        else:
            die('Only 32bit ELF supported')

    def _garbage(self, n):
        out = ''
        while len(out) < n:
            x = random.choice(self.garbage)
            out += x if isinstance(x, str) else pint(x)
        return out[:n]

    def _generate32(self):
        out = []
        chain = self._chain
        self._chain = []
        p = p32
        def garbage():
            return self._garbage(4)

        payload = []
        offset = [0]

        def pargs(args):
            out = []
            for a in args:
                if   a is None:
                    out.append(garbage())
                elif isinstance(a, int):
                    out.append(p(a))
                elif hasattr(a, '__iter__'):
                    packed = pargs(a)
                    payload.extend(packed)
                    out.append(offset[0])
                    for a in packed:
                        if isinstance(a, int):
                            offset[0] += 4
                        else:
                            offset[0] += len(a)
                else:
                    if isinstance(a, str):
                        a += '\x00'
                    a = flat(a)
                    payload.append(a)
                    out.append(offset[0])
                    offset[0] += len(a)
            return out

        for i in range(len(chain)):
            type, link = chain[i]
            islast = i == len(chain) - 1
            issndlast = i == len(chain) - 2
            if type == 'raw':
                out += pargs(link)
            elif type == 'call':
                target, pivot, args = link
                out.append(p(target))
                if len(args) > 0:
                    if islast:
                        out.append(garbage())
                        out += pargs(args)
                    elif issndlast and chain[i + 1][0] == 'call' and \
                      len(chain[i + 1][1][2]) == 0:
                        # the last target has no arguments, so go straight to it
                        out.append(p(chain[i + 1][1][0]))
                        out += pargs(args)
                        break
                    else:
                        if pivot is None:
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
            elif type == 'migrate':
                if not islast:
                    die('Migrate must be last link in chain')
                esp, ebp = link
                gp = self._gadgets['popebp']
                gl = self._gadgets['leave']
                if len(gp) == 0 and len(gl) == 0:
                    die('Could not find set-EBP and leave gadgets needed to migrate')
                gp = gp[0]
                gl = gl[0]
                if ebp is None:
                    out += [p(gp), p(esp-4), p(gl)]
                else:
                    out += [p(gp), p(esp), p(gl)]
                    self.raw(ebp)
            else:
                die('Unknown ROP-link type')
        offset = len(out) * 4
        out_ = out + payload
        out = []
        for o in out_:
            if isinstance(o, int):
                if self._load_addr is None:
                    die('Load address of ROP chain not known; can\'t use structures')
                out.append(p(offset + o + self._load_addr))
            else:
                out.append(o)
        self._load_addr = self._next_load_addr
        self._next_load_addr = None
        return ''.join(out)

    def __str__(self):
        return self.flush()

    def __flat__(self):
        return self.flush()

    def __repr__(self):
        return str(self)

    def __add__(x, y):
        return str(x) + str(y)

    def __radd__(x, y):
        return str(y) + str(x)

    def __getitem__(self, x):
        return self._resolve(x)

    def chain(self, *args):
        if len(args) % 2 <> 0:
            args = args + ((),)
        args = group(2, args)
        for f, a in args:
            self.call(f, a)
        return self
