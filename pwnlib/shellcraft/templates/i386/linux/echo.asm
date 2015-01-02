<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.constants.linux.i386 import SYS_write %>
<%page args="string, sock = 'ebp'"/>
<%docstring>Writes a string to a file descriptor</%docstring>

${i386.pushstr(string, append_null = False)}
${i386.mov('eax', SYS_write)}
${i386.mov('ebx', sock)}
${i386.mov('ecx', 'esp')}
${i386.mov('edx', len(string))}
    int 0x80

