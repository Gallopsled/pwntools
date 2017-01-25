<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>sendfile64(out_fd, in_fd, offset, count) -> str

Invokes the syscall sendfile64.

See 'man 2 sendfile64' for more information.

Arguments:
    out_fd(int): out_fd
    in_fd(int): in_fd
    offset(off64_t*): offset
    count(size_t): count
Returns:
    ssize_t
</%docstring>
<%page args="out_fd, in_fd, offset, count"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['out_fd', 'in_fd', 'offset', 'count']
    argument_values = [out_fd, in_fd, offset, count]
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
    /* sendfile64(out_fd=${repr(out_fd)}, in_fd=${repr(in_fd)}, offset=${repr(offset)}, count=${repr(count)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_sendfile64')}