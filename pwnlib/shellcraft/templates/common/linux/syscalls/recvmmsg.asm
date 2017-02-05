<%
import pwnlib.abi
import pwnlib.constants
import pwnlib.shellcraft
%>
<%docstring>recvmmsg(fd, vmessages, vlen, flags, tmo) -> str

Invokes the syscall recvmmsg.

See 'man 2 recvmmsg' for more information.

Arguments:
    fd(int): fd
    vmessages(mmsghdr*): vmessages
    vlen(unsigned): vlen
    flags(int): flags
    tmo(timespec*): tmo
Returns:
    int
</%docstring>
<%page args="fd=0, vmessages=0, vlen=0, flags=0, tmo=0"/>
<%
    abi = pwnlib.abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = pwnlib.shellcraft.registers.current()

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['fd', 'vmessages', 'vlen', 'flags', 'tmo']
    argument_values = [fd, vmessages, vlen, flags, tmo]

    # Figure out which register arguments can be set immediately
    register_arguments = dict()
    string_arguments = dict()
    dict_arguments = dict()
    array_arguments = dict()

    for name, arg in zip(argument_names, argument_values):
        if arg in allregs:
            index = argument_names.index(name)
            target = regs[index]
            register_arguments[target] = arg
        elif name in can_pushstr and isinstance(arg, str):
            string_arguments[name] = arg
        elif name in can_pushstr_array and isinstance(arg, dict):
            array_arguments[name] = ['%s=%s' % (k,v) for (k,v) in arg.items()]
        elif name in can_pushstr_array and isinstance(arg, (list, tuple)):
            array_arguments[name] = arg
        else:
            index = argument_names.index(name)
            target = regs[index]
            register_arguments[target] = arg

    # Some syscalls have different names on various architectures
    syscalls = ['__NR_recvmmsg']

    for syscall in syscalls:
        syscall = getattr(pwnlib.constants, syscall, None)
        if syscall:
            break
%>
    /* recvmmsg(fd=${repr(fd)}, vmessages=${repr(vmessages)}, vlen=${repr(vlen)}, flags=${repr(flags)}, tmo=${repr(tmo)}) */
    ${pwnlib.shellcraft.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${pwnlib.shellcraft.pushstr(arg, append_null=('\x00' not in arg))}
    ${pwnlib.shellcraft.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${pwnlib.shellcraft.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${pwnlib.shellcraft.syscall(syscall)}