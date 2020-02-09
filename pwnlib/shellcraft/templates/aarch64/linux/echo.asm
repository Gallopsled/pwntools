<% from pwnlib.shellcraft import aarch64 %>
<%page args="string, sock = '1'"/>
<%docstring>
Writes a string to a file descriptor

Example:

    >>> run_assembly(shellcraft.echo('hello\n', 1)).recvline()
    b'hello\n'

</%docstring>

${aarch64.pushstr(string, append_null = False)}
${aarch64.linux.write(sock, 'sp', len(string))}
