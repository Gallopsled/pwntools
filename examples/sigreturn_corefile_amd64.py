from pwn import *
context.arch='amd64'
frame = SigreturnFrame()

registers = ['rax', 'rbx', 'rcx', 'rdx',
             'rdi', 'rsi', 'rbp', 'rsp',
             'rip',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

for index, register in enumerate(registers):
    setattr(frame, register, index)

assembly = '\n'.join([
    shellcraft.read(constants.STDIN_FILENO, 'rsp', 1024),
    shellcraft.sigreturn()
])

binary = ELF.from_assembly(assembly)

io = binary.process()
io.flat(frame)
io.wait()
assert io.poll() == -11

corefile = io.corefile

for index, register in enumerate(registers):
    value = getattr(corefile, register)
    if index != value:
        log.error("%s != %i (%i)" % (register, index, value))
    else:
        log.success("%s == %i" % (register, value))
