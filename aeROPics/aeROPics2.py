#!/usr/bin/env python2
import lib.aeropiclib.gadgets as gadgets
import lib.aeropiclib.readelf as readelf
import re
import pwn
from pwn import log
from pwn import util
from pwn import process
from pwn.i386 import nops

class symbols(dict):
    def __getattr__ (self, name):
        if name in self.keys():
            return util.p32(self.get(name))
        else: return
    def __repr__(self):
        st = ''
        for key in sorted(self.keys()):
            st += key + "\t" * (6-len(key)/8) + hex(self.get(key)) + "\n"
        return st
    def __getitem__(self, item):
        return self.__getattr__(item)

class aeROPics(object):
    def __init__(self, filename):
        self.__ropfinder = gadgets.ROPGadget()
        self.__filename = filename
        self.__stacks = []
        self.gadgets = {}
        self.NOP = nops
        self.__load_gadgets_from_file()

    def __load_gadgets_from_file(self, trackback=3):
        log.waitfor('Loading symbols')
        self.__ropfinder.generate(self.__filename, trackback)
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
        return ''.join(self.__stacks)


