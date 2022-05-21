<% from pwnlib.shellcraft import thumb %>
<%page args="string, sock = '1'"/>
<%docstring>
Writes a string to a file descriptor

Example:

    >>> run_assembly(shellcraft.echo('hello\n', 1)).recvline()
    b'hello\n'

</%docstring>

${thumb.pushstr(string, append_null = False)}
${thumb.linux.syscall('SYS_write', sock, 'sp', len(string))}
