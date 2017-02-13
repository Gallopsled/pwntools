<%
  from pwnlib import shellcraft
%>
<%page args="filename, mode='O_RDONLY'"/>
<%docstring>
Opens a file
</%docstring>
<%
  AT_FDCWD=-100
%>
    ${shellcraft.pushstr(filename)}
    ${shellcraft.syscall('SYS_openat', AT_FDCWD, 'sp', mode, 0)}
