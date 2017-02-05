<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>sigaction(sig, act, oact) -> str

Invokes the syscall sigaction.

See 'man 2 sigaction' for more information.

Arguments:
    sig(int): sig
    act(sigaction*): act
    oact(sigaction*): oact
Returns:
    int
</%docstring>
<%page args="sig=0, act=0, oact=0"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['sig', 'act', 'oact']
    argument_values = [sig, act, oact]

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
    syscalls = ['__NR_sigaction']

    for syscall in syscalls:
        syscall = getattr(constants, syscall, None)
        if syscall:
            break
%>
    /* sigaction(sig=${repr(sig)}, act=${repr(act)}, oact=${repr(oact)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall(syscall)}