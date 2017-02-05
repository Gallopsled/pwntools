<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>mmap(addr, length, prot, flags, fd, offset) -> str

Invokes the syscall mmap.

See 'man 2 mmap' for more information.

Arguments:
    addr(void*): addr
    len(size_t): len
    prot(int): prot
    flags(int): flags
    fd(int): fd
    offset(off_t): offset
Returns:
    void*
</%docstring>
<%page args="addr=0, length=0, prot=0, flags=0, fd=0, offset=0"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['addr', 'length', 'prot', 'flags', 'fd', 'offset']
    argument_values = [addr, length, prot, flags, fd, offset]

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
    /* mmap(addr=${repr(addr)}, length=${repr(length)}, prot=${repr(prot)}, flags=${repr(flags)}, fd=${repr(fd)}, offset=${repr(offset)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_mmap2')}