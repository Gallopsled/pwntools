<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>ioperm(from, num, turn_on) -> str

Invokes the syscall ioperm.

See 'man 2 ioperm' for more information.

Arguments:
    from(unsigned): from
    num(unsigned): num
    turn_on(int): turn_on
Returns:
    int
</%docstring>
<%page args="from, num, turn_on"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['from', 'num', 'turn_on']
    argument_values = [from, num, turn_on]
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
    /* ioperm(from=${repr(from)}, num=${repr(num)}, turn_on=${repr(turn_on)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_ioperm')}