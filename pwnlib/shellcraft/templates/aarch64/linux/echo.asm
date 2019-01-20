<% from pwnlib.shellcraft import aarch64 %>
<%page args="string, sock = '1'"/>
<%docstring>
Writes a string to a file descriptor

Example:

.. doctest::
   :skipif: not binutils_aarch64 or not qemu_aarch64

    >>> run_assembly(shellcraft.echo('hello\n', 1)).recvline()
    'hello\n'

</%docstring>

${aarch64.pushstr(string, append_null = False)}
${aarch64.linux.write(sock, 'sp', len(string))}
