<% from pwnlib.shellcraft import arm %>
<%page args="string, sock = '1'"/>
<%docstring>
Writes a string to a file descriptor

Example:

    >>> run_assembly(shellcraft.echo('hello\n', 1)).recvline()
    'hello\n'

</%docstring>

${arm.pushstr(string, append_null = False)}
${arm.linux.syscall('SYS_write', sock, 'sp', len(string))}
