from pwn import *
context.arch='aarch64'
frame = SigreturnFrame()

registers = ['x%i' % i for i in range(0, 31)]
registers += ['sp', 'pc']


for index, register in enumerate(registers):
    setattr(frame, register, index)

assembly = '\n'.join([
    shellcraft.read(constants.STDIN_FILENO, 'sp', 1024),
    shellcraft.syscall(constants.SYS_rt_sigreturn)
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
