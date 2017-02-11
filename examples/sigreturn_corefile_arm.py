from pwn import *

context.arch='arm'
frame = SigreturnFrame()

registers = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
             'r8', 'r9', 'r10', 'fp', 'ip', 'sp', 'pc', 'lr']


for index, register in enumerate(registers):
    setattr(frame, register, index)

assembly = '\n'.join([
    shellcraft.read(constants.STDIN_FILENO, 'sp', 1024),
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
