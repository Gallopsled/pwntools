<%
from pwnlib.shellcraft.mips.linux import syscall
%>
<%docstring>Sigreturn system call</%docstring>
  ${syscall('SYS_sigreturn', )}
