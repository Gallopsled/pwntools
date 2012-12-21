from pwn import die, ELF, u8, p32, p64, randoms
from collections import defaultdict

class ROP:
    def __init__(self, file):
        self.elf = ELF(file)
        if self.elf.elfclass <> 'ELF32':
            die('Can only build ROP chains for 32bit ELF')
        self._poprets = defaultdict(list)

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

        self._load_poprets()

        self._chain = []

    def _load_poprets(self):
        self._load_poprets32()

    def _load_poprets32(self):
        addesp = '\x83\xc4'
        popr = map(chr, [0x58, 0x59, 0x5a, 0x5b, 0x5d, 0x5e, 0x5f])
        popa = '\x61'
        ret  = '\xc3'
        for name, sec in self.elf.sections.items():
            if 'X' not in sec['flags']: continue
            data = self.elf.section(name)
            addr = sec['addr']
            i = 0
            while True:
                i = data.find(ret, i)
                if i == -1: break
                s = [(i, 0)]
                while len(s) > 0:
                    off, size = s.pop(0)
                    gaddr = addr + off
                    self._poprets[size].append(gaddr)
                    if data[off - 1] in popr:
                        s.append((off - 1, size + 1))
                    if data[off - 1] == popa:
                        s.append((off - 1, size + 7))
                    if data[off - 3:off - 1] == addesp:
                        x = u8(data[off - 1])
                        if x % 4 == 0:
                            s.append((off - 3, size + x // 4))
                i += 1

    def _resolve(self, x):
        if x is None or isinstance(x, int):
            return x
        for y in [self.plt, self.symbols, self.sections]:
            if x in y:
                return y[x]
        die('Could not resolve `%s\'' % x)

    def call(self, target, args = ()):
        '''Irrelevant arguments should be marked by a None'''
        target = self._resolve(target)
        args = map(self._resolve, args)
        if hasattr(args, '__iter__'):
            args = list(args)
        else:
            args = [args]
        self._chain.append((target, args))

    def generate(self):
        return self.generate32()

    def generate32(self):
        out = []
        chain = self._chain
        rets = self._poprets
        garbage = lambda: randoms(4)
        for i in range(len(chain)):
            target, args = chain[i]
            args = map(p32, args)
            out.append(p32(target))
            final = i == len(chain) - 1
            if len(args) > 0:
                if final:
                    out.append(garbage())
                else:
                    # find suitable popret
                    pivot = None
                    for size in rets.keys():
                        if size >= len(args):
                            pivot = p32(rets[size][0])
                            break
                    for _ in range(size - len(args)):
                        args.append(garbage())
                    if pivot is None:
                        die('Could not generate ROP chain')
                    out.append(pivot)
            out += args
        return ''.join(out)


# alias
class load(ROP): pass

# import lib.aeropiclib.gadgets as gadgets
# import lib.aeropiclib.readelf as readelf
# import re, pwn, pwn.i386

# global _curr_ae
# _curr_ae = None

# class address(str):
#     def __add__(self, y):
#         # The address of each element in symbols should be wrapped into the address class when inserted, NOT when retrieved... fix me plx
#         if isinstance(self, str):
#             return pwn.p32(pwn.u32(self) + y)

# class symbols(dict):
#     def __getattr__ (self, name):
#         if name in self.keys():
#             return address(pwn.p32(self.get(name)))
#         else: return

#     def __fmt(self, key):
#         return key + "\t" * (6-len(key)/8) + hex(self.get(key)) + "\n"
#     def __repr__(self):
#         st = ''
#         for key in sorted(self.keys()):
#             st += self.__fmt(key)
#         return st
#     def __getitem__(self, item):
#         return self.__getattr__(item)
#     def __call__(self, item):
#         st = ''
#         for key in sorted(self.keys()):
#             if isinstance(item, str):
#                 if item in key:
#                     st += self.__fmt(key)
#             if isinstance(item, int):
#                 value = hex(self.get(key))
#                 if hex(item) in value:
#                     st += self.__fmt(key)
#         print st

# class load(object):
#     __recent_call_args = 0

#     def __init__(self, filename):
#         self.__ropfinder = gadgets.ROPGadget()
#         self.__filename = filename
#         self.__stacks = []
#         self.NOP = pwn.i386.nops
#         self.__load_gadgets_from_file()

#         global _curr_ae
#         _curr_ae = self
#         globals()['plt'] = self.plt
#         globals()['got'] = self.got
#         globals()['segments'] = self.segments
#         globals()['libc'] = self.libc
#         globals()['gadgets'] = self.gadgets

#     def __load_gadgets_from_file(self, trackback=3):
#         pwn.waitfor('Loading symbols')
#         try:
#             self.__ropfinder.generate(self.__filename, trackback)
#         except:
#             pwn.die('could not load file')
#             return
#         self.gadgets = symbols(dict([(item.strip(';;').replace(' ; ','__')[:-1].replace(' ','_'), addr) for (item, addr) in self.__ropfinder.asm_search('%')]))
#         elfreader = readelf.Elf()
#         elfreader.read_headers(self.__filename)
#         self.segments = symbols(elfreader._headers)
#         elfreader.read_plt(self.__filename)
#         self.plt = symbols(elfreader._plt)
#         elfreader.read_got(self.__filename)
#         self.got = symbols(elfreader._got)
#         elfreader.read_libc_offset(self.__filename)
#         self.libc = symbols(elfreader._libc_offset)
#         pwn.succeeded()

#     def _findpopret(self, num):
#         for key in sorted(m for m in self.gadgets.keys() if m.startswith('pop')):
#             match = len(re.findall('\w{3}\_\w{3}', key))
#             if match == num:
#                 return self.gadgets[key]
#         return False

#     def _lookup(self, symb):
#         addr = self.plt[symb]
#         if addr is not None:
#             pwn.info("found symbol <%s> in plt" % symb)
#             return addr

#         addr = self.segments[symb]
#         if addr is not None:
#             pwn.info("found symbol <%s> in segments" % symb)
#             return addr

#         pwn.die("Could not find symbol <%s>" % symb)


#     def call(self, arg, argv=None, return_to=None):
#         if isinstance(arg, str) and not isinstance(arg, address):
#             arg = self._lookup(arg)
#         if isinstance(arg, int):
#             arg = pwn.p32(arg)

#         if not argv:
#             if self.__recent_call_args > 0: # then this is a return addr to the previous function
#                 self.__stacks.insert(-self.__recent_call_args, arg)
#             else:
#                 self.append(arg)
#             self.__recent_call_args = 0
#         else:
#             argv = [self._lookup(a) if type(a) == str else a for a in argv]
#             num = 1 if isinstance(argv, str) else len(argv)
#             self.__recent_call_args = num

#             self.append(arg)
#             if return_to:
#                 self.append(return_to)
#             else:
#                 ret = self._findpopret(num)
#                 if ret:
#                     self.append(ret)
#             for item in argv:
#                 self.append(item)

#     # def __setitem__(self, i, y):
#     #     self.add(i, y)

#     # def __getattr__ (self, name):
#     #     if name in self.gadgets.keys():
#     #         return self.gadgets[name]

#     def append(self, item):
#         self.__stacks.append(item)

#     def __repr__(self):
#         return pwn.flat(self.__stacks)

#     # def pwnit(self, *argv):
#     #     p = pwn.process(self.__filename, *argv)
#     #     p.interactive('pwnshell$ ')

#     def portable(self, portable_type='sh', pipe=False):
#         def _string(s):
#             out = []
#             for c in s:
#                 co = ord(c)
#                 out.append('\\x%02x' % co)
#             return ''.join(out)

#         if portable_type == 'sh':
#             print "Here's a portable, have fun!"
#             if pipe:
#                 print "python -c \"print '%s'\" | %s" % (_string(str(self)), self.__filename)
#             else:
#                 print "%s $(python -c \"print '%s'\"" % (self.__filename, _string(str(self)))
#             print ""

# def call(arg, argv=None, return_to=None):
#     if not _curr_ae:
#         return False
#     else:
#         _curr_ae.call(arg, argv, return_to)

# def data(arg):
#     if not _curr_ae:
#         return False
#     else:
#         _curr_ae.append(arg)

# def pwnit(*argv):
#     if not _curr_ae:
#         return False
#     _curr_ae.pwnit(*argv)

# def payload():
#     if not _curr_ae:
#         return False
#     return str(_curr_ae)

# def portable(portable_type='sh', pipe=False):
#     if not _curr_ae:
#         return False
#     if portable_type == 'sh':
#         _curr_ae.portable(portable_type, pipe)
