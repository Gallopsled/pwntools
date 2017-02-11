
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="mqdes, notification"/>
<%docstring>
Invokes the syscall mq_notify.  See 'man 2 mq_notify' for more information.

Arguments:
    mqdes(mqd_t): mqdes
    notification(sigevent): notification
</%docstring>

    ${syscall('SYS_mq_notify', mqdes, notification)}
