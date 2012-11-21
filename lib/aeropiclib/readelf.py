#!/usr/bin/env python
#
#       readelf.py
#
#       Copyright 2010 Long Le Dinh <longld at vnsecurity.net>
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

import os
import sys
from subprocess import *

# ELF file headers class
# a python wrapper for for readelf (binutils)
class Elf:
    # readelf/objdump binary
    READELF = "/usr/bin/readelf"
    OBJDUMP = "/usr/bin/objdump"
    # default libc
#    LIBC = "/lib/libc.so.6"
    # interesting functions
    FUNCTIONS = ["__libc_start_main", "strcpy", "memcpy", "printf", "sprintf"]
    LDD = "/usr/bin/ldd"

    def __init__(self):
        self._headers = {  "_plt": 0,
                           "_text": 0,
                           "_got": 0,
                           "_got_plt": 0,
                           "_data": 0,
                           "_bss": 0,
                           "_comment": 0, 
                           "base": 0,
                        }
        self._plt = {}
        self._got = {}
        self._libc_offset = {"mprotect":0, "read":0, "execve":0, "execv":0, "execvp":0, "system":0, "setreuid":0, "seteuid":0}

        if os.access(self.READELF, os.X_OK) == False or os.access(self.OBJDUMP, os.X_OK) == False:
            print "Cannot execute %s, please install/check binutils" % self.READELF
            sys.exit(-1)

    # parse single line of output
    def _parse_line(self, line):
        out = line.replace("[", "").replace("]", "").split()
        #print out
        addr = int(out[3], 16)
        off = int(out[4], 16)

        return (addr, off)

    def find_libc(self, binfile):
        cmd = self.LDD + " " + binfile
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        out = out.split("\n")

        for line in out:
            if 'libc.so.' in line:
                l = line.split('=> ')[1]
                libc = l.split(' (')[0]
                return libc
            

    # parse output from readelf
    def read_headers(self, binfile):
        cmd = self.READELF + " -W -S " + binfile
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        out = out.split("\n")

        for line in out:
            for h in self._headers.keys():
                if line.find(" " + h.replace('_','.') + " ") != -1 and self._headers[h] == 0:
                    (addr, off) = self._parse_line(line)
                    self._headers[h] = addr
                    if h == "_text":
                        self._headers["base"] = addr - off
                    if h == "_comment":
                        self._headers["_comment"] = self._headers["base"] + off

        cmd = self.READELF + " -s " + binfile
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        out = out.split("\n")
        out = [item for item in out if "GLOBAL" in item and "DEFAULT" in item and "FUNC" in item and not "UND" in item]
        for line in out:
            line = line.split()
            name, addr = line[-1], line[1]
            if not name in self._headers:
                self._headers[name] = int(addr, 16)

    # get address of specific header
    def get_header(self, name):
        return self._headers[name]

    # print elf headers
    def print_headers(self):
        print "--- ELF headers ---"
        print "Header \t\t Address"
        for (k, v) in self._headers.iteritems():
            print "%s \t %s" % (k.ljust(10), hex(v))

    # get PLT entries
    def read_plt(self, binfile):
        cmd = self.OBJDUMP + " -d " + binfile
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        out = out.split("\n")

        for line in out:
            if line.find("@plt>:") != -1:
                ent = line.split()
                addr = int(ent[0], 16)
                func = ent[1].split("@")[0][1:]
                self._plt[func] = addr

        return True

    # get PLT address of specific funtion
    def get_plt(self, name):
        if name in self._plt:
            return self._plt[name]
        else:
            return -1

    # print PLT entries
    def print_plt(self):
        print "--- PLT entries ---"
        print "Function \t\t Address"
        for (k, v) in self._plt.iteritems():
            print "%s \t %s" % (k.ljust(20), hex(v))

    # get GOT entries
    def read_got(self, binfile):
        cmd = self.READELF + " -r " + binfile
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        out = out.split("\n")

        for line in out:
            if line.find("_JUMP_SLOT") != -1:
                ent = line.split()
                if len(ent) < 5: continue
                addr = int(ent[0], 16)
                func = ent[4]
                self._got[func] = addr

        return True

    # get GOT entry address of specific funtion
    def get_got(self, name):
        if name in self._got:
            return self._got[name]
        else:
            return -1

    # print GOT table
    def print_got(self):
        print "--- GOT table ---"
        print "Function \t\t Address"
        for (k, v) in self._got.iteritems():
            print "%s \t %s" % (k.ljust(20), hex(v))

    # get libc offset for functions in plt and some predefined ones
    def read_libc_offset(self, binfile, *functions):
        libc = self.find_libc(binfile)
        cmd = self.READELF + " -s " + libc
        out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
        out = out.split("\n")

        if functions == (): # read default functions
            flist = self._libc_offset.keys() + self._plt.keys()
        else:
            flist = functions
        for line in out:
            for func in flist:
                if line.find(" " + func + "@@GLIBC") != -1:
                    ent = line.split()
                    addr = int(ent[1], 16)
                    self._libc_offset[func] = addr

        return True

    # get GOT entry address of specific funtion
    def get_libc_offset(self, name):
        if name in self._libc_offset:
            return self._libc_offset[name]
        else: # re-read 
            self.read_libc_offset(self.LIBC, name)
            if name in self._libc_offset:
                return self._libc_offset[name]
            else:
                return 0

    # print libc offsets
    def print_libc_offset(self):
        print "--- LIBC offset ---"
        print "Function \t\t Address"
        for (k, v) in self._libc_offset.iteritems():
            print "%s \t %s" % (k.ljust(20), hex(v))

if __name__ == '__main__':
    import sys
    binfile = sys.argv[1]
    e = Elf()
    e.read_headers(binfile)
    e.read_plt(binfile)
    e.read_got(binfile)
    e.read_libc_offset(binfile)
    print "Base address:", hex(e.get_header("base"))
    e.print_headers()
    e.print_plt()
    e.print_got()
    e.print_libc_offset()
