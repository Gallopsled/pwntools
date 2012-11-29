#!/usr/bin/env python2
import lib.aeropiclib.gadgets as gadgets
import lib.aeropiclib.readelf as readelf
import re
import pwn
from pwn import flat
from pwn import log
from pwn import util
from pwn import process
from pwn.i386 import nops

global curr_ae, got, plt, segments
curr_ae = None
got = None
plt = None
segments = None

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

class aeROPics(object):
    __recent_call_args = 0

    def __init__(self, filename):
        self.__ropfinder = gadgets.ROPGadget()
        self.__filename = filename
        self.__stacks = []
        self.gadgets = {}
        self.NOP = nops
        self.__load_gadgets_from_file()

        global curr_ae
        curr_ae = self
        global plt, got, segments
        plt = self.plt
        got = self.got
        segments = self.segments

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

    def __findpopret(self, num):
        for key in sorted(m for m in self.rops.keys() if m.startswith('pop')):
            match = len(re.findall('\w{3}\_\w{3}', key))
            if match == num:
                return self.rops[key]
        return False

    def call(self, arg, argv=None, return_to=None):
        if not argv:
            if self.__recent_call_args > 0: # then this is actually a return_to address
                log.info("Detecting a singleton address after a function call, pushing this as the functions return address")
                self.__stacks.insert(-self.__recent_call_args, arg)
            else:
                log.info("Inserting singleton")
                self.append(arg) # so this is the very first... better know what you're doing
            self.__recent_call_args = 0
        else:
            num = len(argv)
            self.__recent_call_args = num

            if return_to:
                self.append(arg)
                self.append(return_to)
                [self.append(item) for item in argv]
                log.success("Adding ROP gadget to payload: %s%s ret: %s" % (arg, str(argv), return_to))
            else:
                ret = self.__findpopret(num)
                if ret:
                    self.append(arg)
                    self.append(ret)
                    [self.append(item) for item in argv]
                    log.success("Adding ROP gadget to payload: %s%s" % (arg, str(argv)))
                else:
                    self.append(arg)
                    [self.append(item) for item in argv]
                    log.success("Adding ROP gadget to payload: %s%s" % (arg, str(argv)))
                    log.warning("No return address was found, you better know what you're doing!")
            # else:
            #     ret = self.__findpopret(num)


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

    def append(self, item, args=None):
        # if args:
        #     num_args = len(args)
        self.__stacks.append(item)

    def __repr__(self):
        return flat(self.__stacks)

    def pwnit(self, *argv):
        p = process(self.__filename, *argv)
        p.interactive('pwnshell$ ')

def ropcall(arg, argv=None, return_to=None):
    if not curr_ae:
        return False
    else:
        curr_ae.call(arg, argv, return_to)

def pwnit(*argv):
    if not curr_ae:
        return False
    else:
        curr_ae.pwnit(*argv)
