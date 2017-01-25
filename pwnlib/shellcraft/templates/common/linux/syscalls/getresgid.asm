<%
import pwnlib.shellcraft as sc
import pwnlib.abi as abi
%>
<%docstring>getresgid(rgid, egid, sgid) -> str

Invokes the syscall getresgid.

See 'man 2 getresgid' for more information.

Arguments:
    rgid(gid_t*): rgid
    egid(gid_t*): egid
    sgid(gid_t*): sgid
Returns:
    int
</%docstring>
<%page args="rgid, egid, sgid"/>
<%
    abi = abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]

    can_pushstr = []
    can_pushstr_array = []

    argument_names = ['rgid', 'egid', 'sgid']
    argument_values = [rgid, egid, sgid]
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
    /* getresgid(rgid=${repr(rgid)}, egid=${repr(egid)}, sgid=${repr(sgid)}) */
    ${sc.setregs(register_arguments)}
%for name, arg in string_arguments.items():
    ${sc.pushstr(arg, append_null=('\x00' not in arg))}
    ${sc.mov(regs[argument_names.index(name)], abi.stack)}
%endfor
%for name, arg in array_arguments.items():
    ${sc.pushstr_array(regs[argument_names.index(name)], arg)}
%endfor
    ${sc.syscall('SYS_getresgid')}