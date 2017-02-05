<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>mknod(path, mode, dev) -> str

Invokes the syscall mknod.

See 'man 2 mknod' for more information.

Arguments:
    path(char*): path
    mode(mode_t): mode
    dev(dev_t): dev
Returns:
    int
</%docstring>
<%page args="path=0, mode=0, dev=0"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = ['path']
    can_pushstr_array = []

    argument_names = ['path', 'mode', 'dev']
    argument_values = [path, mode, dev]

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
    syscalls = ['__NR_mknod']

    for syscall in syscalls:
        syscall = getattr(constants, syscall, None)
        if syscall:
            break
%>
    /* mknod(path=${repr(path)}, mode=${repr(mode)}, dev=${repr(dev)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall(syscall)}