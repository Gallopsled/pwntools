<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>mremap(addr, old_len, new_len, flags, vararg) -> str

Invokes the syscall mremap.

See 'man 2 mremap' for more information.

Arguments:
    addr(void*): addr
    old_len(size_t): old_len
    new_len(size_t): new_len
    flags(int): flags
    vararg(int): vararg
Returns:
    void*
</%docstring>
<%page args="addr, old_len, new_len, flags, vararg"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['addr', 'old_len', 'new_len', 'flags', 'vararg']
    argument_values = [addr, old_len, new_len, flags, vararg]
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
    ${sc.syscall('SYS_mremap')}