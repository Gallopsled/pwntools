from pwn import *
context.kernel='amd64'
frame = SigreturnFrame()

registers = ['eax', 'ebx', 'ecx', 'edx',
             'edi', 'esi', 'ebp', 'esp',
             'eip']

for index, register in enumerate(registers):
    setattr(frame, register, index)

assembly = '\n'.join([
    shellcraft.read(constants.STDIN_FILENO, 'esp', 1024),
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
