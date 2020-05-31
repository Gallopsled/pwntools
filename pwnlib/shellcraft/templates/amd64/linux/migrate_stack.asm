<% from pwnlib.shellcraft import amd64 %>
<%page args="size=0x100000, fd=0"/>
<%docstring>Migrates to a new stack.</%docstring>

    ${amd64.linux.mmap_rwx(size)}
    ${amd64.mov('rsp', 'rax')}

    add rsp, ${hex((size * 3 // 4) & ~7)}
