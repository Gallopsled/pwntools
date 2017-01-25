<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
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
<%page args="fd, vmessages, vlen, flags, tmo"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['fd', 'vmessages', 'vlen', 'flags', 'tmo']
    argument_values = [fd, vmessages, vlen, flags, tmo]
    arguments = dict(zip(argument_names, argument_values))

    # Figure out which register arguments can be set immediately
    register_arguments = dict()
    string_arguments = dict()
    dict_arguments = dict()
    array_arguments = dict()

    for name, arg in arguments.items():
        if name in can_pushstr and isinstance(arg, str):
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
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_recvmmsg')}