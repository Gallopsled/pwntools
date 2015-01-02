<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.constants.linux.i386 import SYS_write %>
<%page args="string, sock = 'ebp'"/>
<%docstring>Writes a string to a file descriptor</%docstring>

${i386.pushstr(string, append_null = False)}
${i386.linux.syscall('SYS_write', sock, 'esp', len(string))}
