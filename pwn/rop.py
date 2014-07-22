import pwn

class _FuncOrConst(int):
    def __call__ (self, *args):
        self._func(args)

class ROP(object):
    '''class that construct a ROP chain.
    Example:
        from pwn import *
        r = ROP('path/to/binary')
        r.call('recv', [4, r.bss(100), 100, 0]) #recieve 100 bytes of shellcode to .bss + 100
        r.mprotect(r.bss(100)) #mark it executable
        r.call(r.bss(100), []) #run it!
        print enhex(str(r))'''
    def __init__(self, path, garbage = 0xdeadbeef):
        if isinstance(path, pwn.ELF):
            self.elf = path
        else:
            self.elf = pwn.elf.load(path)

        self.garbage = pwn.tuplify(garbage)

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
        self._gadget_cache = {}
        self._load_addr = None
        self._next_load_addr = None
        self._load_gadgets()

    def __getattr__(self, name):
        def func(args):
            self.call(name, args)
        x = _FuncOrConst(self._resolve(name))
        x._func = func
        return x

    def gadget(self, what, avoid = ''):
        if what in self._gadget_cache:
            return self._gadget_cache[(what, avoid)]
        gs = []
        err = 'Unknown gadget type: "%s"' % what
        if   what == 'ret':
            gs = self._gadgets.get('popret', {}).get(0, [])
        elif what == 'leave':
            gs = self._gadgets.get('leave', [])
        elif what == 'popebp':
            gs = self._gadgets.get('popebp', [])
        elif what.startswith('pop'):
            if what.startswith('popret'):
                offset = what[6:]
            else:
                if what[-3:] == 'ret':
                    what = what[:-3]
                offset = what[3:]
            if offset.isdigit():
                offset = int(offset)
            elif offset == '':
                offset = 1
            else:
                pwn.die(err)
            gs = self._gadgets.get('popret', {}).get(offset, [])
        else:
            pwn.die(err)
        for g in gs:
            gstr = pwn.pint(g)
            if all(c not in gstr for c in avoid):
                self._gadget_cache[(avoid, what)] = g
                return g

    def mprotect(self, addr, numb = 4096):
        '''does all the stuff that you want mprotect to do, but can't remember how to do
(i.e. marks address executable, and takes care of page alignment)'''
        # align addr down to nearest page boundary and adjust numb accordingly
        numb += addr | 4095
        addr = addr & ~4095
        self.call('mprotect', (addr, numb, 7))

    def bss(self, offset=0):
        '''returns the address of .bss+offset. Get place to store data'''
        return self.sections['.bss'] + offset

    def extra_libs(self, libs):
        self.elf.extra_libs(libs)

    def load_library(self, file, addr, relative_to = None):
        '''loads a library at an absolute address or relative to a known symbol'''
        import os
        syms = {}

        if not os.path.exists(file):
            if file in self.elf.libs:
                file = self.elf.libs[file]
            else:
                pwn.die('Could not load library, file %s does not exist.' % file)

        for k, v in pwn.elf.symbols(file).items():
            if '@@' in k:
                k = k[:k.find('@@')]
            syms[k] = v
        offset = addr
        if relative_to:
            if relative_to not in syms:
                pwn.die('Could not load library relative to "%s" -- no such symbol', relative_to)
            offset -= syms[relative_to]['addr']
        for k, v in syms.items():
            self.symbols[k] = v['addr'] + offset

    def dump(self):
        chain = self._generate32(reset=False)
        last  = 0
        for i in xrange(0, len(chain), 4):
            data = chain[i:i+4]
            addr = pwn.u32(data)
            try:    sym = next(k for k,v in self.symbols.items() if v==addr)
            except: sym = ''
            print "%08x: %08x %s" % (i, addr, sym or '')
            last = addr

    def add_symbol(self, symbol, addr):
        self.symbols[symbol] = addr

    def set_load_addr(self, addr):
        self._load_addr = addr

    def _load_gadgets(self):
        if self.elf.elfclass == 'ELF32':
            self._load32_popret()
            self._load32_migrate()

    def _load32_popret(self):
        from collections import defaultdict
        leaesp_byte = '\x8d\x64\x24'
        leaesp_word = '\x8d\xa4\x24'
        addesp_byte = '\x83\xc4'
        addesp_word = '\x81\xc4'
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
                    if data[off - 3:off - 1] == addesp_byte:
                        x = pwn.u8(data[off - 1])
                        if x % 4 == 0 and x < 128:
                            s.append((off - 3, size + x // 4))
                    if data[off - 6:off - 1] == addesp_word:
                        x = pwn.u32(data[off - 4])
                        if x % 4 == 0:
                            s.append((off - 3, size + x // 4))
                    if data[off - 4:off - 1] == leaesp_byte:
                        x = pwn.u8(data[off - 1])
                        if x % 4 == 0 and x < 128:
                            s.append((off - 3, size + x // 4))
                    if data[off - 7:off - 1] == leaesp_word:
                        x = pwn.u32(data[off - 4])
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
            idxs = pwn.findall(data, leave)
            ls += map(lambda i: i + addr, idxs)
            idxs = pwn.findall(data, popebp)
            ps += map(lambda i: i + addr, idxs)
        self._gadgets['leave'] = ls
        self._gadgets['popebp'] = ps

    def _resolve(self, x):
        if x is None or pwn.isint(x):
            return x
        for y in [self.symbols, self.plt, self.sections]:
            if x in y:
                return y[x]
        return self.sections.get('.' + x, False)
        # pwn.die('Could not resolve `%s\'' % x)

    def _pivot(self, args):
        pivot = None
        rets = self._gadgets['popret']
        for size in sorted(rets.keys()):
            if size >= len(args):
                pivot = rets[size][0]
                break
        if pivot is None:
            for i in pwn.findall(args, None):
                if i in rets.keys():
                    res = self._pivot(args[i + 1:])
                    if res is None: continue
                    pivot, size = res
                    args[i] = pivot
                    pivot = rets[i][0]
                    size += i + 1
                    break
        if pivot is not None:
            self.symbols['stackfix %i slots' % size] = pivot
            return (pivot, size)

    def migrate(self, sp, bp = None):
        '''migrate from the current ROP chain to another one.  Great for staged ROP'ing.
        Must be the last item in a chain. Example:
           rop = ROP('...')
           rop.read(5, rop.data_buf, 0x1000)
           rop.migrate(rop.data_buf)'''
        self._next_load_addr = sp
        self._chain.append(('migrate', (sp, bp)))
        return self

    def set_frame(self, addr):
        if self.elf.elfclass == 'ELF32':
            self._set_frame32(addr)
        else:
            pwn.die('Only 32bit ELF supported')

    def _set_frame32(self, addr):
        gs = self._gadgets['popebp']
        if gs <> []:
            self.raw(gs[0], addr)
        else:
            pwn.die('Could not find set-EBP gadget')

    def call(self, target, args = (), pivot = None):
        '''Irrelevant arguments should be marked by a None'''
        target = self._resolve(target)
        self._chain.append(('call', (target, pivot, pwn.tuplify(args))))
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
            pwn.die('Only 32bit ELF supported')

    def _garbage(self, n):
        import random
        out = ''
        while len(out) < n:
            x = random.choice(self.garbage)
            out += x if isinstance(x, str) else pwn.pint(x)
        return out[:n]

    def _generate32(self, reset=True):
        out = []
        chain = self._chain

        if reset:
            self._chain = []

        p = pwn.p32
        def garbage():
            return self._garbage(4)

        payload = []
        offset = [0]

        def pargs(args):
            out = []
            for a in args:
                if   a is None:
                    out.append(garbage())
                elif pwn.isint(a):
                    out.append(p(a))
                elif hasattr(a, '__iter__'):
                    packed = pargs(a)
                    payload.extend(packed)
                    out.append(offset[0])
                    for a in packed:
                        if pwn.isint(a):
                            offset[0] += 4
                        else:
                            offset[0] += len(a)
                else:
                    if isinstance(a, str):
                        a += '\x00'
                    a = pwn.flat(a)
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
                                pwn.die('Could not find gadget for pivoting %d arguments' % len(args))
                            pivot, size = res
                            args = pargs(args)
                            for _ in range(size - len(args)):
                                args.append(garbage())
                        out.append(p(pivot))
                        out += args
            elif type == 'migrate':
                if not islast:
                    pwn.die('Migrate must be last link in chain')
                esp, ebp = link
                gp = self.gadget('popebp')
                gl = self.gadget('leave')
                if not gp or not gl:
                    pwn.die('Could not find set-EBP and leave gadgets needed to migrate')
                if ebp is None:
                    out += [p(gp), p(esp-4), p(gl)]
                else:
                    out += [p(gp), p(esp), p(gl)]
                    self.raw(ebp)
            else:
                pwn.die('Unknown ROP-link type')
        offset = len(out) * 4
        out_ = out + payload
        out = []
        for o in out_:
            if pwn.isint(o):
                if self._load_addr is None:
                    pwn.die('Load address of ROP chain not known; can\'t use structures')
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
        return "<ROP instance on file: %s>" % self.elf._path #str(self)

    def __add__(self, other):
        return str(self) + str(other)

    def __radd__(self, other):
        return str(other) + self.flush()

    def __coerce__ (self, other):
        if pwn.isint(other) and self._load_addr:
            return (self._load_addr, other)
        elif isinstance(other, str):
            return (self.flush(), other)
        else:
            pwn.die('Could not coerce ROP.  Other value was: %r' % other)

    def __dir__(self):
        return dir(type(self)) + list(self.__dict__)

    def chain(self, *args):
        if len(args) % 2 <> 0:
            args = args + ((),)
        args = pwn.group(2, args)
        for f, a in args:
            self.call(f, a)
        return self
