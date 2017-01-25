<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>vmsplice(fdout, iov, count, flags) -> str

Invokes the syscall vmsplice.

See 'man 2 vmsplice' for more information.

Arguments:
    fdout(int): fdout
    iov(iovec*): iov
    count(size_t): count
    flags(unsigned): flags
Returns:
    ssize_t
</%docstring>
<%page args="fdout, iov, count, flags"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['fdout', 'iov', 'count', 'flags']
    argument_values = [fdout, iov, count, flags]

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
    /* vmsplice(fdout=${repr(fdout)}, iov=${repr(iov)}, count=${repr(count)}, flags=${repr(flags)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_vmsplice')}