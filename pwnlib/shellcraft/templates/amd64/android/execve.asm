<%
    from pwnlib.shellcraft import amd64, registers
    from pwnlib.abi import linux_amd64_syscall as abi
%>
<%docstring>
Execute a different process.

Attempts to perform some automatic detection of types.
Otherwise, the arguments behave as normal.

- If ``path`` is a string that is not a known register,
  it is pushed onto the stack.
- If ``argv`` is an array of strings, it is pushed onto
  the stack, and NULL-terminated.
- If ``envp`` is an dictionary of {string:string},
  it is pushed onto the stack, and NULL-terminated.

Example:

    >>> path = '/bin/sh'
    >>> argv = ['sh', '-c', 'echo Hello, $NAME; exit $STATUS']
    >>> envp = {'NAME': 'zerocool', 'STATUS': 3}
    >>> sc = shellcraft.amd64.linux.execve(path, argv, envp)
    >>> io = run_assembly(sc)
    >>> io.recvall()
    'Hello, zerocool\n'
    >>> io.poll(True)
    3
</%docstring>
<%page args="path = '/system/bin//sh', argv=[], envp={}"/>
<%
if isinstance(envp, dict):
    envp = ['%s=%s' % (k,v) for (k,v) in envp.items()]

args_reg = abi.register_arguments[2]
env_reg  = abi.register_arguments[3]
%>
% if isinstance(argv, (list, tuple)):
    ${amd64.pushstr_array(abi.register_arguments[3], argv)}
    <% argv = abi.register_arguments[3] %>
% endif
% if isinstance(envp, (list, tuple)):
    ${amd64.pushstr_array(abi.register_arguments[2], envp)}
    <% envp = abi.register_arguments[2] %>
% endif
% if isinstance(path, str) and not registers.is_register(path):
    ${amd64.pushstr(path)}
    <% path = 'rsp' %>
%endif
    ${amd64.syscall('SYS_execve', path, argv, envp)}

