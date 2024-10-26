<%
  from pwnlib.shellcraft.amd64 import syscall, pushstr
  from pwnlib.shellcraft import common
%>
<%page args="filename, fd=1"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
</%docstring>
<%
raise Exception("not implemented, please use 'cat2'")
%>
    ${pushstr(filename)}
    ${syscall('SYS_open', 'rsp', 'O_RDONLY', 'rdx')}
    /* osx: int sendfile(int fd, int s, off_t offset, off_t *len, struct sf_hdtr *hdtr, int flags); */
    /* linux: ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count); */
    ${syscall('SYS_sendfile', fd, 'rax', 0, 0x7fffffff)}
