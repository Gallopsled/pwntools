<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>mq_open(name, oflag, vararg) -> str

Invokes the syscall mq_open.

See 'man 2 mq_open' for more information.

Arguments:
    name(char*): name
    oflag(int): oflag
    vararg(int): vararg
Returns:
    mqd_t
</%docstring>
<%page args="name, oflag, vararg"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = ['name']
    can_pushstr_array = []

    argument_names = ['name', 'oflag', 'vararg']
    argument_values = [name, oflag, vararg]

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
    /* mq_open(name=${repr(name)}, oflag=${repr(oflag)}, vararg=${repr(vararg)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_mq_open')}