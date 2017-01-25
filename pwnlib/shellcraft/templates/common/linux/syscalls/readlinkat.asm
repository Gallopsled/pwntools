<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>readlinkat(fd, path, buf, len) -> str

Invokes the syscall readlinkat.

See 'man 2 readlinkat' for more information.

Arguments:
    fd(int): fd
    path(char*): path
    buf(char*): buf
    len(size_t): len
Returns:
    ssize_t
</%docstring>
<%page args="fd, path, buf, len"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]

    can_pushstr = ['path', 'buf']
    can_pushstr_array = []

    argument_names = ['fd', 'path', 'buf', 'len']
    argument_values = [fd, path, buf, len]
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
    /* readlinkat(fd=${repr(fd)}, path=${repr(path)}, buf=${repr(buf)}, len=${repr(len)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_readlinkat')}