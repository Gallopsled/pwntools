
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="mqdes, msg_ptr, msg_len, msg_prio, abs_timeout"/>
<%docstring>
Invokes the syscall mq_timedsend.  See 'man 2 mq_timedsend' for more information.

Arguments:
    mqdes(mqd_t): mqdes
    msg_ptr(char): msg_ptr
    msg_len(size_t): msg_len
    msg_prio(unsigned): msg_prio
    abs_timeout(timespec): abs_timeout
</%docstring>

    ${syscall('SYS_mq_timedsend', mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)}
