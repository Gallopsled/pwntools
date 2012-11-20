#       gadgets.py
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

import trie
import distorm3 as distorm
import sys
try:
    import cPickle as pickle
except:
    import pickle

import readelf
import hashlib
import os
import pprint

RET_CODE = {"ret" : "\xc3"} # return opcode
# useless instructions, we will not put these to gadgets
BAD_INSTS = ["DB", "CALL 0x", "JMP 0x", "JN", "JE", "JZ", "JB", "JA", "JAE", "JO", "IN", "HLT", "LES", "FLD"]

# ROP x86 asm gadget class
class ROPGadget:

    def __init__(self, option = distorm.Decode32Bits, debug = 0):
        self.__asmgadget = trie.Trie()
        self.__asmgadget.set_case_sensitive(False)
        self.__search_depth = 3 # default depth for instruction search
        self.__backward_depth = 3 # default number of insts for backward processing
        self.__max_duplicate = 3 # default number duplicate gadgets, keep somes for enough offset alternatives
        self.__gadget_info = {"hash": "", "name": "", "base_addr": 0, "data_addr": 0}
        self.__debug = debug
        self.__decode_option = option

    #
    # disassemble the binary with diStorm64
    #
    def __disass(self, filename, offset = 0, option = distorm.Decode32Bits):
        code = open(filename, 'rb').read()
        disass = distorm.DecodeGenerator(offset, code, option)
        return disass

    #
    # generate the gadgets from binary file, can be called multiple times
    #
    def generate(self, filename, backward_depth = 3):
        code = open(filename, 'rb').read()

        self.set_backward_depth(backward_depth)
        # get binary info: md5sum, name, base_addr, data_addr
        self.__gadget_info["hash"] = self.__md5sum(filename)
        self.__gadget_info["name"] = os.path.basename(filename)
        (base_addr, data_addr) = self.__get_elf_address(filename)
        self.__gadget_info["base_addr"] = base_addr
        self.__gadget_info["data_addr"] = data_addr

        block_size = 1024 * 1024 # process 1 MB a time
        block_count = len(code)/block_size + 1
#        print >>sys.stderr, "Generating gadgets for " + filename + " with backward depth=" + str(backward_depth)
#        print >>sys.stderr, "It may take few minutes depends on the depth and file size..."
        for count in range(block_count):
#            print >>sys.stderr, "Processing code block %d/%d" % (count+1, block_count)
            block_start = count * block_size
            disassembly = distorm.DecodeGenerator(block_start, code[block_start:block_start + block_size], self.__decode_option)

            bincode = "" # keep track of hex code
            for (offset, size, instruction, hexdump) in disassembly:
                hexbyte = hexdump.replace(" ", "")
                if len(hexbyte) % 2 != 0:  # invalid hexdump?, cut the last char
                    hexbyte = hexbyte[:-1]
                hexbyte = hexbyte.decode('hex')
                bincode += hexbyte
                l = len(hexbyte)
                i = hexbyte.find(RET_CODE["ret"]) # find RET in opcode

                if i != -1: # RET found
                    self.__LOG("Found RET at 0x%x" % (long(offset) + i))
                    # get back (__backward_depth * 8) bytes, enough?
                    hexbyte = bincode[-((l-i) + (self.__backward_depth * 8)) : -(l-i)]
                    self.__process_backward(hexbyte, base_addr + offset + i - 1)

#        print >>sys.stderr, "Generated " + str(self.__asmgadget.get_size()) + " gadgets"
        
        return True

    #
    # backward process for code from RET
    #
    def __process_backward(self, hexbyte, end_offset):
        self.__LOG("Backward process: " + hexbyte.encode('hex') + ", offset: " + hex(end_offset))
        RET = RET_CODE["ret"]
        l = len(hexbyte)
        for i in range(l):
            found_bad = 0
            code = (hexbyte[(l-i-1) : l])
            code = code + RET
            disassembly = distorm.DecodeGenerator(end_offset - i, code, self.__decode_option)
            disassembly = list(disassembly)
            if len(disassembly) <= self.__backward_depth + 1: # max backward depth not reach
                if disassembly[-1][-1].lower() != RET.encode('hex'): # invalid sequence
                    continue
                asmcode = []
                for (offset, size, instruction, hexdump) in disassembly[:-1]:
                    asmcode += ("".join(instruction).replace(",", " ")).split() + [";"]

                # skip bad instructions
                s = " ".join(asmcode)
                if "CALL 0x" in s or "JMP 0x" in s:
                    continue
                self.__LOG(asmcode)
                if set(asmcode) & set(BAD_INSTS) != set([]):
                    continue

                #asmcode += [RET_CODE.keys()[1] + " "]
                value = (" ".join(asmcode).lower() + ";", end_offset - i)
                self.__LOG("i = %d, value = %x, code: %s" % (i, value[1], asmcode))
                self.__insert_asmcode(asmcode, value)

    #
    # insert asmcode to asmgadget trie
    # special case: [eax + 0xdeadbeef], eax + 0xdeadbeef, [eax + esi * n],
    #
    def __insert_asmcode(self, instruction, value):
        result = []
        code = "@".join(instruction).replace("@;", "").replace(" ", "").lower()
        code = code.replace("[", "[@")
        code = code.replace("]", "@]")
        code = code.replace("+", "@+@")
        code = code.replace("-", "@-@")
        code = code.replace("*", "@*@")
        code = code.split("@")
        result = self.__asmgadget.retrieve(code)
        if len(result) < self.__max_duplicate: # still need offset for this gadget
            self.__LOG("inserted code: " + " - ".join(code))
            self.__asmgadget.insert(code, value)

        return True

    #
    # convert hexbyte string to list
    #
    def __hex_to_list(self, hexbyte):
        result = []
        for i in range(len(hexbyte)/2):
            result.append(hexbyte[i*2 : (i+1)*2])

        return result

    #
    # set the depth for backward search
    #
    def set_backward_depth(self, depth):
        self.__backward_depth = depth

    #
    # get the hash of gadgets
    #
    def info(self):
        return self.__gadget_info

    #
    # compute MD5 sum of the file
    #
    def __md5sum(self, filename):
        infile = open(filename, 'rb')
        content = infile.read()
        infile.close()
        m = hashlib.md5() # don't forget to "import hashlib"
        m.update(content)
        md5 = m.hexdigest() # now the md5 variable contains the MD5 sum

        return md5

    #
    # get ELF header info
    #
    def __get_elf_address(self, filename):
        elf = readelf.Elf()
        elf.read_headers(filename)
        base_addr = elf.get_header("base")
        data_addr = elf.get_header("_data")

        return (base_addr, data_addr)

    #
    # load the gadgets from data file, can be called multiple times
    #
    def load_asm(self, filename):
        fp = open(filename, 'rb')
        print >>sys.stderr, "Loading asm gadgets from file:", filename, "..."
        self.__gadget_info = pickle.load(fp)
        self.__asmgadget = pickle.load(fp)
        fp.close()
        print >>sys.stderr, "Loaded", self.__asmgadget.get_size(), "gadgets"
        print >>sys.stderr, "ELF base address:", hex(self.__gadget_info["base_addr"])

    #
    # dump the gadgets to data file
    #
    def save_asm(self, filename):
        fp = open(filename, 'w')
        print >>sys.stderr, "Dumping asm gadgets to file:", filename, "..."
        pickle.dump(self.__gadget_info, fp, 0)
        pickle.dump(self.__asmgadget, fp, 0)
        fp.close()

    #
    # search for asm code in text format
    #
    def asm_search(self, asmcode, constraints = [set([]), set(["-00"])], depth = 1):
        # e.g mov eax,ebx
        self.__LOG("Searching for " + asmcode)
        result = []
        search_code = asmcode.upper().replace(",", " ").split()
        if depth == 2:
            search_code = search_code + ["*"]
        if depth == 3:
            search_code = ["*"] + search_code + ["*"]

        result = self.__asmgadget.retrieve(search_code)

        # filter bad instructions & bad addresses
        if result != []:
            self.__LOG(result)
            result = self.__filter_instruction(result, constraints[0])
            result = self.__filter_address(result, constraints[1])

        # filter duplicate gadgets, just need to display few
        return result

    #
    # filter for denied inst or register in asm code
    # filter format: ["-esp", "-sub"]
    #
    def __filter_instruction(self, retcode, constraints = set([])):
        result = []
        if constraints == set([]): return retcode
        for code in retcode:
            found = 0
            for filter in constraints:
                self.__LOG(filter + ":" + code[0])
                if code[0].lower().find(filter[1:].lower()) != -1:
                    found = 1
                    break
            if found == 0:
                result.append(code)

        return result

    #
    # filter for denied chars in offset address
    # filter format: ["-00", "-0a"]
    #
    def __filter_address(self, retcode, constraints = set([])):
        result = []
        if constraints == set([]): return retcode
        for code in retcode:
            for filter in constraints:
                self.__LOG(filter + ":" + hex(code[1])[2:-1].rjust(8, "x"))
                if hex(code[1])[2:-1].rjust(8, "0").find(filter[1:]) %2 != 0:
                    result.append(code)

        return result

    #
    # print debug __LOG
    #
    #
    def __LOG(self, message):
        if self.__debug != 0:
            pprint.pprint(message)
