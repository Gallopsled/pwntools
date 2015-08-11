<% from pwnlib.shellcraft.i386 import push, mov %>
<% from pwnlib.shellcraft.i386.linux import syscall %>
<% from pwnlib.shellcraft import common %>
<%docstring>
Retrieves the highest numbered PID on the system, according to
the sysctl kernel.pid_max.
</%docstring>
<%
CTL_KERN=1
KERN_PIDMAX=55

"""
struct __sysctl_args {
    int    *name;    /* integer vector describing variable */
    int     nlen;    /* length of this vector */
    void   *oldval;  /* 0 or address where to store old value */
    size_t *oldlenp; /* available room for old value,
                        overwritten by actual size of old value */
    void   *newval;  /* 0 or address of new value */
    size_t  newlen;  /* size of new value */
};
"""
%>
    push ebp
    ${push(0xffff)}
    mov  ebp, esp    /* ebp = oldval and frame pointer R*/
    ${push(4)}
    mov  eax, esp    /* eax = oldlenp */
    ${push(CTL_KERN)}
    ${push(KERN_PIDMAX)}
    mov ecx, esp    /* ecx = name */
    ${push(0)}      /* newlen */
    ${push(0)}      /* newval */
    ${push('eax')}  /* oldlenp */
    ${push('ebp')}  /* oldval  */
    ${push(2)}      /* nlen */
    ${push('ecx')}  /* name */
    ${syscall('SYS__sysctl', 'esp')}
    mov esp, ebp
    pop eax
    pop ebp
