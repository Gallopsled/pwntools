<% from pwnlib.shellcraft.arm.linux import syscall %>


<%docstring>Sigreturn system call</%docstring>
    ${syscall('SYS_sigreturn', )}
