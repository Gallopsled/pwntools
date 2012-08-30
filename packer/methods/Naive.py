import os
import pwn
class Naive:

    def __init__(self,shellcode,key='0xff'):
        self.name = "xor packer"
        self.description = "Basic xor packer, isnt really safe"
        self.shellcode = shellcode
        self.key = key
        self.packed = ''
        self.packer = ''
        #for the tester
        self.arch = '32'
        #self.arch = '64'

    def makeunpacker(self,testing=False):
        length = len(self.shellcode)
        if length < 257:
            strlen = 'mov bl '+str(length)
        elif length <2**16:
            strlen = 'mov bx '+str(length)
        else:   
            strlen = 'mox ebx '+str(length)
            
        assembler = 'call trampolin\
            unpacker:\
            pop eax\
            xor ebx,ebx\
            mov edx,'+self.key+''\
            + strlen+ '\
            sub ebx,eax\
            xor [al],dl\
            lea ebx,[ebx-1]\
            loop:\
            cmp eax,ebx\
            jne loop\
            '
        if not testing:
            assembler = assembler + 'call eax;'
        assembler = assembler + 'trampolin:jmp unpacker;'
        self.packer = asm(assembler)
    def pack(self):
        tmp = []
        for x in shellcode:
            tmp.append(self.key ^ x)
        self.packed = ''.join(tmp)

    def getPackage(self):
        return self.packer + self.packed
    def test(self):
        #test for null bytes
        for cha in self.packed:
            if ord(cha)==0:
                sys.exit("The patcked code contains null bytes")
        for cha in self.packer:
            if ord(cha)==0:
                sys.exit("The packer code contains null bytes")
        p = os.popen("test/tester"+self.arch,"r")
        unpacked = ""
        line = p.readline()
        while line:
            unpacked += line
        if not unpacked == shellcode:
            sys.exit("The unpacked payload didnt match the starting payload")
