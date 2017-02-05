<%
import pwnlib.abi
import pwnlib.constants
import pwnlib.shellcraft
%>
<%docstring>prlimit64(pid, resource, new_limit, old_limit) -> str

Invokes the syscall prlimit64.

See 'man 2 prlimit64' for more information.

Arguments:
    pid(pid_t): pid
    resource(rlimit_resource): resource
    new_limit(rlimit64*): new_limit
    old_limit(rlimit64*): old_limit
Returns:
    int
</%docstring>
<%page args="pid=0, resource=0, new_limit=0, old_limit=0"/>
<%
    abi = pwnlib.abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = pwnlib.shellcraft.registers.current()

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['pid', 'resource', 'new_limit', 'old_limit']
    argument_values = [pid, resource, new_limit, old_limit]

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
    syscalls = ['SYS_prlimit64']

    for syscall in syscalls:
        if hasattr(pwnlib.constants, syscall):
            break
    else:
        raise Exception("Could not locate any syscalls: %r" % syscalls)
%>
    /* prlimit64(pid=${repr(pid)}, resource=${repr(resource)}, new_limit=${repr(new_limit)}, old_limit=${repr(old_limit)}) */
    ${pwnlib.shellcraft.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${pwnlib.shellcraft.pushstr(arg, append_null=('\x00' not in arg))}
    ${pwnlib.shellcraft.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${pwnlib.shellcraft.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${pwnlib.shellcraft.syscall(syscall)}