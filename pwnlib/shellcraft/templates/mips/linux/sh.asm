<% from pwnlib.shellcraft import mips %>
<%docstring>Execute /bin/sh</%docstring>

${mips.execve('//bin/sh', ['sh'], {})}
