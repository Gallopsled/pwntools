<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>putpmsg(fildes, ctlptr, dataptr, band, flags) -> str

Invokes the syscall putpmsg.

See 'man 2 putpmsg' for more information.

Arguments:
    fildes(int): fildes
    ctlptr(strbuf*): ctlptr
    dataptr(strbuf*): dataptr
    band(int): band
    flags(int): flags
Returns:
    int
</%docstring>
<%page args="fildes, ctlptr, dataptr, band, flags"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['fildes', 'ctlptr', 'dataptr', 'band', 'flags']
    argument_values = [fildes, ctlptr, dataptr, band, flags]

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
%>
    /* putpmsg(fildes=${repr(fildes)}, ctlptr=${repr(ctlptr)}, dataptr=${repr(dataptr)}, band=${repr(band)}, flags=${repr(flags)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_putpmsg')}