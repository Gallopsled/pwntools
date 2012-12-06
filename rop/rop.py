#!/usr/bin/env python2
import lib.aeropiclib.gadgets as gadgets
import lib.aeropiclib.readelf as readelf
import re
from pwn import flat, log, util, process, p32
from pwn.i386 import nops

global _curr_ae
_curr_ae = None

class address(str):
    def __add__(self, y):
        # The address of each element in symbols should be wrapped into the address class when inserted, NOT when retrieved... fix me plx
        if isinstance(self, str):
            return util.p32(util.u32(self) + y)

class symbols(dict):
    def __getattr__ (self, name):
        if name in self.keys():
            return address(util.p32(self.get(name)))
        else: return

    def __fmt(self, key):
        return key + "\t" * (6-len(key)/8) + hex(self.get(key)) + "\n"
    def __repr__(self):
        st = ''
        for key in sorted(self.keys()):
            st += self.__fmt(key)
        return st
    def __getitem__(self, item):
        return self.__getattr__(item)
    def __call__(self, item):
        st = ''
        for key in sorted(self.keys()):
            if isinstance(item, str):
                if item in key:
                    st += self.__fmt(key)
            if isinstance(item, int):
                value = hex(self.get(key))
                if hex(item) in value:
                    st += self.__fmt(key)
        print st

class load(object):
    __recent_call_args = 0

    def __init__(self, filename):
        self.__ropfinder = gadgets.ROPGadget()
        self.__filename = filename
        self.__stacks = []
        self.gadgets = {}
        self.NOP = nops
        self.__load_gadgets_from_file()

        global _curr_ae
        _curr_ae = self
        globals()['plt'] = self.plt
        globals()['got'] = self.got
        globals()['segments'] = self.segments
        globals()['libc'] = self.libc
        globals()['rops'] = self.rops

    def __load_gadgets_from_file(self, trackback=3):
        log.waitfor('Loading symbols')
        try:
            self.__ropfinder.generate(self.__filename, trackback)
        except:
            log.failed()
            return
        self.rops = symbols(dict([(item.strip(';;').replace(' ; ','__')[:-1].replace(' ','_'), addr) for (item, addr) in self.__ropfinder.asm_search('%')]))
        elfreader = readelf.Elf()
        elfreader.read_headers(self.__filename)
        self.segments = symbols(elfreader._headers)
        elfreader.read_plt(self.__filename)
        self.plt = symbols(elfreader._plt)
        elfreader.read_got(self.__filename)
        self.got = symbols(elfreader._got)
        elfreader.read_libc_offset(self.__filename)
        self.libc = symbols(elfreader._libc_offset)
        log.succeeded()

    def _findpopret(self, num):
        for key in sorted(m for m in self.rops.keys() if m.startswith('pop')):
            match = len(re.findall('\w{3}\_\w{3}', key))
            if match == num:
                return self.rops[key]
        return False

    def call(self, arg, argv=None, return_to=None):
        if isinstance(arg, str) and not isinstance(arg, address):
            log.info("searching for %s in plt" % arg)
            arg = self.plt[arg]
            if arg == None:
                log.info("symbol not found")
                return
        if isinstance(arg, int):
            arg = p32(arg)

        if not argv:
            if self.__recent_call_args > 0: # then this is a return addr to the previous function
                self.__stacks.insert(-self.__recent_call_args, arg)
            else:
                self.append(arg)
            self.__recent_call_args = 0
        else:
            num = 1 if isinstance(argv, str) else len(argv)
            self.__recent_call_args = num

            self.append(arg)
            if return_to:
                self.append(return_to)
            else:
                ret = self._findpopret(num)
                if ret:
                    self.append(ret)
            [self.append(item) for item in argv]


    def add(self, name, value):
        if isinstance(value, str):
            val = value
        else:
            val = util.p32(value)
        self.gadgets.update({name: val})

    def __setitem__(self, i, y):
        self.add(i, y)

    def __getattr__ (self, name):
        if name in self.gadgets.keys():
            return self.gadgets[name]

    def append(self, item):
        self.__stacks.append(item)

    def __repr__(self):
        return flat(self.__stacks)

    # def pwnit(self, *argv):
    #     p = process(self.__filename, *argv)
    #     p.interactive('pwnshell$ ')

    def portable(self, portable_type='sh', pipe=False):
        def _string(s):
            out = []
            for c in s:
                co = ord(c)
                out.append('\\x%02x' % co)
            return ''.join(out)

        if portable_type == 'sh':
            print "Here's a portable, have fun!"
            if pipe:
                print "python -c \"print '%s'\" | %s" % (_string(str(self)), self.__filename)
            else:
                print "%s $(python -c \"print '%s'\"" % (self.__filename, _string(str(self)))
            print ""

def call(arg, argv=None, return_to=None):
    if not _curr_ae:
        return False
    else:
        _curr_ae.call(arg, argv, return_to)

def data(arg):
    if not _curr_ae:
        return False
    else:
        _curr_ae.append(arg)

def pwnit(*argv):
    if not _curr_ae:
        return False
    _curr_ae.pwnit(*argv)

def payload():
    if not _curr_ae:
        return False
    return str(_curr_ae)

def portable(portable_type='sh', pipe=False):
    if not _curr_ae:
        return False
    if portable_type == 'sh':
        _curr_ae.portable(portable_type, pipe)
