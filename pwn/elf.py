import os, sys, re
from subprocess import *
from pwn import die
from pwn.log import waitfor, succeeded

# readelf/objdump binaries
_READELF = '/usr/bin/readelf'
_OBJDUMP = '/usr/bin/objdump'

class ELF:
    '''A parsed ELF file'''
    def __init__(self, file):
        waitfor('Loading ELF file `%s\'' % os.path.basename(file))
        self.sections = {}
        self.symbols = {}
        self.plt = {}
        self.got = {}
        self.elfclass = None
        self._file_data = None

        if not (os.access(file, os.R_OK) and os.path.isfile(file)):
            die('File %s is not readable or does not exist' % file)

        self._file = file

        def check(f):
            if not (os.access(f, os.X_OK) and os.path.isfile(f)):
                die('Executable %s needed for readelf.py, please install binutils' % f)

        check(_READELF)
        check(_OBJDUMP)

        self._load_elfclass()
        self._load_sections()
        self._load_symbols()
        self._load_plt_got()
        succeeded()

    def _load_elfclass(self):
        # -h : ELF header
        cmd = _READELF + ' -h ' + self._file
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        self.elfclass = re.findall('Class:\s*(.*$)', out, re.MULTILINE)[0]

    def _load_sections(self):
        # -W : wide output
        # -S : sections
        cmd = _READELF + ' -W -S ' + self._file
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        field = '\s+(\S+)'
        posint = '[123456789]\d*'
        flags = '\s+([WAXMSILGTExOop]*)'
        lines = re.findall('^\s+\[\s*' + posint + '\]' + field * 6 + flags, out, re.MULTILINE)

        for name, _type, addr, off, size, _es, flgs in lines:
            addr = int(addr, 16)
            off = int(off, 16)
            size = int(size, 16)
            self.sections[name] = {'addr'  : addr,
                                   'offset': off,
                                   'size'  : size,
                                   'flags' : flgs,
                                   }

    def _load_symbols(self):
        # -s : symbol table
        cmd = _READELF + ' -s ' + self._file
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        field = '\s+(\S+)'
        lines = re.findall('^\s+\d+:' + field * 7 + '$', out, re.MULTILINE)

        for addr, size, type, _bind, _vis, _ndx, name in lines:
            addr = int(addr, 16)
            size = int(size, 10)
            if addr <> 0 and name <> '':
                self.symbols[name] = {'addr': addr,
                                      'size': size,
                                      'type': type,
                                      }

    # this is crazy slow -- include this feature in the all-python ELF parser
    def _load_plt_got(self):
        cmd = _OBJDUMP + ' -d ' + self._file
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        got32 = '[^j]*jmp\s+\*0x(\S+)'
        got64 = '[^#]*#\s+(\S+)'
        lines = re.findall('([a-fA-F0-9]+)\s+<([^@<]+)@plt>:(%s|%s)' % (got32, got64), out)

        for addr, name, _, gotaddr32, gotaddr64 in lines:
            addr = int(addr, 16)
            gotaddr = int(gotaddr32 or gotaddr64, 16)
            self.plt[name] = addr
            self.got[name] = gotaddr

    def _load_data(self):
        if self._file_data is None:
            with open(self._file, 'r') as f:
                self._file_data = f.read()

    def _read(self, addr, size):
        self._load_data()
        for sec in self.sections.values():
            if 'A' not in sec['flags']: continue
            if addr >= sec['addr'] and addr < sec['addr'] + sec['size']:
                size = min(size, sec['size'] - (sec['addr'] - addr))
                addr = addr - sec['addr'] + sec['offset']
                return self._file_data[addr:addr + size]

    def symbol(self, name):
        if name in self.symbols:
            sym = self.symbols[name]
            addr = sym['addr']
            size = sym['size']
            data = self._read(addr, size)
            if data is None:
                die('Symbol %s does not live in any section' % name)
            else:
                return data
        else:
            die('No symbol named %s' % name)

    def section(self, name):
        if name in self.sections:
            self._load_data()
            sec = self.sections[name]
            offset = sec['offset']
            size = sec['size']
            return self._file_data[offset:offset + size]
        else:
            die('No section named %s' % name)

    def read(self, addr, numb):
        out = []
        while numb > 0:
            data = self._read(addr, numb)
            if data is None:
                die('Offset %x does not live in any section' % addr)
            out.append(data)
            size = len(data)
            numb -= size
            addr += size
        return ''.join(out)
