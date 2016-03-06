<% from pwnlib.shellcraft import i386 %>
<%page args="string, sock = 'ebp'"/>
<%docstring>Writes a string to a file descriptor</%docstring>

${i386.pushstr(string, append_null = False)}
${i386.linux.syscall('SYS_write', sock, 'esp', len(string))}
