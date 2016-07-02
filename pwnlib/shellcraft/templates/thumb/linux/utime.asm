
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="file, file_times"/>
<%docstring>
Invokes the syscall utime.  See 'man 2 utime' for more information.

Arguments:
    file(char): file
    file_times(utimbuf): file_times
</%docstring>

    ${syscall('SYS_utime', file, file_times)}
