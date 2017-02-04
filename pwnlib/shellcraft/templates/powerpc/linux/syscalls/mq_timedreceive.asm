
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="mqdes, msg_ptr, msg_len, msg_prio, abs_timeout"/>
<%docstring>
Invokes the syscall mq_timedreceive.  See 'man 2 mq_timedreceive' for more information.

Arguments:
    mqdes(mqd_t): mqdes
    msg_ptr(char): msg_ptr
    msg_len(size_t): msg_len
    msg_prio(unsigned): msg_prio
    abs_timeout(timespec): abs_timeout
</%docstring>

    ${syscall('SYS_mq_timedreceive', mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)}
