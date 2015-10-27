<%
from pwnlib.shellcraft import i386, registers
from pwnlib.abi import linux_i386_syscall as abi
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
    >>> sc = shellcraft.i386.linux.execve(path, argv, envp)
    >>> io = run_assembly(sc)
    >>> io.recvall()
    'Hello, zerocool\n'
    >>> io.poll(True)
    3
</%docstring>
<%page args="path = '/system/bin//sh', argv=0, envp=0"/>
<%
if isinstance(envp, dict):
    envp = ['%s=%s' % (k,v) for (k,v) in envp.items()]
%>
% if isinstance(argv, (list, tuple)):
    ${i386.pushstr_array(abi.register_arguments[3], argv)}
    <% argv = abi.register_arguments[3] %>
% endif
% if isinstance(envp, (list, tuple)):
    ${i386.pushstr_array(abi.register_arguments[2], envp)}
    <% envp = abi.register_arguments[2] %>
% endif
% if isinstance(path, str) and not registers.is_register(path):
    ${i386.pushstr(path)}
    <% path = 'esp' %>
%endif
    ${i386.syscall('SYS_execve', path, argv, envp)}
