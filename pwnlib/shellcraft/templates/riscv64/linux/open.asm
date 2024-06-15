<%
  from pwnlib import shellcraft
%>
<%page args="filename, flags=0, mode='a3'"/>
<%docstring>
Opens a file
</%docstring>
<%
  AT_FDCWD=-100
%>
    ${shellcraft.pushstr(filename)}
    ${shellcraft.syscall('SYS_openat', AT_FDCWD, 'sp', flags, mode)}
