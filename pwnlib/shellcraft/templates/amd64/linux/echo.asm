<% from pwnlib.shellcraft import amd64 %>
<% from pwnlib.constants.linux.amd64 import SYS_write %>
<%page args="string, sock = 'rbp'"/>
<%docstring>Writes a string to a file descriptor</%docstring>

${amd64.pushstr(string, append_null = False)}
${amd64.mov('rax', SYS_write)}
${amd64.mov('rdi', sock)}
${amd64.mov('rsi', 'rsp')}
${amd64.mov('rdx', len(string))}
    syscall
