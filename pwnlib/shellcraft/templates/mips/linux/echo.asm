<% from pwnlib.shellcraft import mips %>
<%page args="string, sock = 1"/>
<%docstring>Writes a string to a file descriptor</%docstring>

${mips.pushstr(string, append_null = False)}
${mips.linux.syscall('SYS_write', sock, '$sp', len(string))}
