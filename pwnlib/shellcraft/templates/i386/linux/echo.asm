<% from pwnlib.shellcraft import i386 %>
<%page args="string, sock = '1'"/>
<%docstring>
Writes a string to a file descriptor

Example:

.. doctest::
   :skipif: not binutils_i386 or not qemu_i386

    >>> run_assembly(shellcraft.echo('hello', 1)).recvall()
    'hello'

</%docstring>

${i386.pushstr(string, append_null = False)}
${i386.linux.syscall('SYS_write', sock, 'esp', len(string))}
