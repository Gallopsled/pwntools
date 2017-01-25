<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>getgroups(size, list) -> str

Invokes the syscall getgroups.

See 'man 2 getgroups' for more information.

Arguments:
    size(int): size
    list(gid_t*): list
Returns:
    int
</%docstring>
<%page args="size, list"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['size', 'list']
    argument_values = [size, list]
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
    /* getgroups(size=${repr(size)}, list=${repr(list)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_getgroups')}