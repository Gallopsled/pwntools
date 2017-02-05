<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout) -> str

Invokes the syscall mq_timedsend.

See 'man 2 mq_timedsend' for more information.

Arguments:
    mqdes(mqd_t): mqdes
    msg_ptr(char*): msg_ptr
    msg_len(size_t): msg_len
    msg_prio(unsigned): msg_prio
    abs_timeout(timespec*): abs_timeout
Returns:
    int
</%docstring>
<%page args="mqdes=0, msg_ptr=0, msg_len=0, msg_prio=0, abs_timeout=0"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = sc.registers.current()

    can_pushstr = ['msg_ptr']
    can_pushstr_array = []

    argument_names = ['mqdes', 'msg_ptr', 'msg_len', 'msg_prio', 'abs_timeout']
    argument_values = [mqdes, msg_ptr, msg_len, msg_prio, abs_timeout]

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
    syscalls = ['__NR_mq_timedsend']

    for syscall in syscalls:
        syscall = getattr(constants, syscall, None)
        if syscall:
            break
%>
    /* mq_timedsend(mqdes=${repr(mqdes)}, msg_ptr=${repr(msg_ptr)}, msg_len=${repr(msg_len)}, msg_prio=${repr(msg_prio)}, abs_timeout=${repr(abs_timeout)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall(syscall)}