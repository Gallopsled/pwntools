<% from pwnlib.shellcraft import thumb %>
<%page args="string, sock = '1'"/>
<%docstring>
Writes a string to a file descriptor

Example:

.. doctest::
   :skipif: not binutils_aarch64 or not qemu_aarch64

    >>> run_assembly(shellcraft.echo('hello\n', 1)).recvline()
    'hello\n'

</%docstring>

${thumb.pushstr(string, append_null = False)}
${thumb.linux.syscall('SYS_write', sock, 'sp', len(string))}
