from pwn import *
context.arch='aarch64'
frame = SigreturnFrame()

registers = ['x%i' % i for i in range(0, 31)]
registers += ['pc']


for index, register in enumerate(registers):
    setattr(frame, register, index)
frame.sp = 64

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

for register in registers:
    value = getattr(corefile, register)
    index = getattr(frame, register)
    if index != value:
        log.error("%s != %i (%i)" % (register, index, value))
    else:
        log.success("%s == %i" % (register, value))
