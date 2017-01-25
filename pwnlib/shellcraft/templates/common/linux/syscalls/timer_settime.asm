<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>timer_settime(timerid, flags, value, ovalue) -> str

Invokes the syscall timer_settime.

See 'man 2 timer_settime' for more information.

Arguments:
    timerid(timer_t): timerid
    flags(int): flags
    value(itimerspec*): value
    ovalue(itimerspec*): ovalue
Returns:
    int
</%docstring>
<%page args="timerid, flags, value, ovalue"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['timerid', 'flags', 'value', 'ovalue']
    argument_values = [timerid, flags, value, ovalue]

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
    /* timer_settime(timerid=${repr(timerid)}, flags=${repr(flags)}, value=${repr(value)}, ovalue=${repr(ovalue)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_timer_settime')}