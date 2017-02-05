<%
import pwnlib.abi
import pwnlib.constants
import pwnlib.shellcraft
%>
<%docstring>getpmsg(fildes, ctlptr, dataptr, bandp, flagsp) -> str

Invokes the syscall getpmsg.

See 'man 2 getpmsg' for more information.

Arguments:
    fildes(int): fildes
    ctlptr(strbuf*): ctlptr
    dataptr(strbuf*): dataptr
    bandp(int*): bandp
    flagsp(int*): flagsp
Returns:
    int
</%docstring>
<%page args="fildes=0, ctlptr=0, dataptr=0, bandp=0, flagsp=0"/>
<%
    abi = pwnlib.abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = pwnlib.shellcraft.registers.current()

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['fildes', 'ctlptr', 'dataptr', 'bandp', 'flagsp']
    argument_values = [fildes, ctlptr, dataptr, bandp, flagsp]

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
    syscalls = ['__NR_getpmsg']

    for syscall in syscalls:
        if hasattr(pwnlib.constants, syscall):
            break
    else:
        raise Exception("Could not locate any syscalls: %r" % syscalls)
%>
    /* getpmsg(fildes=${repr(fildes)}, ctlptr=${repr(ctlptr)}, dataptr=${repr(dataptr)}, bandp=${repr(bandp)}, flagsp=${repr(flagsp)}) */
    ${pwnlib.shellcraft.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${pwnlib.shellcraft.pushstr(arg, append_null=('\x00' not in arg))}
    ${pwnlib.shellcraft.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${pwnlib.shellcraft.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${pwnlib.shellcraft.syscall(syscall)}