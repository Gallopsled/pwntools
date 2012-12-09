import os, sys, re
from subprocess import *
from pwn import die

# readelf/objdump binaries
_READELF = '/usr/bin/readelf'
_OBJDUMP = '/usr/bin/objdump'

# ELF file headers class
# a python wrapper for for readelf (binutils)
class Elf:
    def __init__(self, file):
        self._sections = {}
        self._symbols = {}
        self._plt = {}
        self._base = None
        self._file_data = None

        if not (os.access(file, os.R_OK) and os.path.isfile(file)):
            die('File %s is not readable or does not exist' % file)

        self._file = file

        def check(f):
            if not (os.access(f, os.X_OK) and os.path.isfile(f)):
                die('Executable %s needed for readelf.py, please install binutils' % f)

        check(_READELF)
        check(_OBJDUMP)


    def _load_sections(self):
        # -W : wide output
        # -S : sections
        cmd = _READELF + ' -W -S ' + self._file
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        field = '\s+(\S+)'
        posint = '[123456789]\d*'
        lines = re.findall('^\s+\[\s*' + posint + '\]' + field * 5, out, re.MULTILINE)

        for name, _type, addr, off, size in lines:
            addr = int(addr, 16)
            off = int(off, 16)
            size = int(size, 16)
            self._sections[name] = (addr, off, size)
            if self._base is None and _type == 'PROGBITS':
                self._base = addr - off

    def _load_symbols(self):
        # -s : symbol table
        cmd = _READELF + ' -s ' + self._file
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        field = '\s+(\S+)'
        lines = re.findall('^\s+\d+:' + field * 7, out, re.MULTILINE)

        for value, size, type, _bind, _vis, _ndx, name in lines:
            value = int(value, 16)
            if value <> 0 and name <> '':
                self._symbols[name] = (value, size, type)

    # this is crazy slow -- include this feature in the all-python ELF parser
    def _load_plt(self):
        cmd = _OBJDUMP + ' -d ' + self._file
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        got32 = '[^j]*jmp\s+\*0x(\S+)'
        got64 = '[^#]*#\s+(\S+)'
        lines = re.findall('([a-fA-F0-9]+)\s+<([^@<]+)@plt>:(%s|%s)' % (got32, got64), out)

        # print lines

        for addr, name, _, gotaddr32, gotaddr64 in lines:
            addr = int(addr, 16)
            gotaddr = int(gotaddr32 or gotaddr64, 16)
            self._plt[name] = (addr, gotaddr)
