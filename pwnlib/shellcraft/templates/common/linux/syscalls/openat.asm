<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>openat(fd, file, oflag, vararg) -> str

Invokes the syscall openat.

See 'man 2 openat' for more information.

Arguments:
    fd(int): fd
    file(char*): file
    oflag(int): oflag
    vararg(int): vararg
Returns:
    int
</%docstring>
<%page args="fd=0, file=0, oflag=0, vararg=0"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = ['file']
    can_pushstr_array = []

    argument_names = ['fd', 'file', 'oflag', 'vararg']
    argument_values = [fd, file, oflag, vararg]

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
    syscalls = ['__NR_openat']

    for syscall in syscalls:
        syscall = getattr(constants, syscall, None)
        if syscall:
            break
%>
    /* openat(fd=${repr(fd)}, file=${repr(file)}, oflag=${repr(oflag)}, vararg=${repr(vararg)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall(syscall)}