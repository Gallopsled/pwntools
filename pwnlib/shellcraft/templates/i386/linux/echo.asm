<% from pwnlib.shellcraft import i386 %>
<%page args="string, sock = '1'"/>
<%docstring>
Writes a string to a file descriptor

Example:

    >>> run_assembly(shellcraft.echo('hello', 1)).recvall()
    'hello'

</%docstring>

${i386.pushstr(string, append_null = False)}
${i386.linux.syscall('SYS_write', sock, 'esp', len(string))}
