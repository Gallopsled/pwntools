<% from pwnlib.shellcraft import amd64 %>
<% from pwnlib.constants.linux import amd64 as constants %>
<%page args="syscall, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None, arg5 = None"/>
<%docstring>
Args: [syscall_number, *args]
    Does a syscall
</%docstring>
% for dst, src in zip(['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9', 'rax'], [arg0, arg1, arg2, arg3, arg4, arg5, syscall]):
  % if src != None:
    <%
      if isinstance(src, (str, unicode)):
          src = getattr(constants, src, src)
    %>
    ${amd64.mov(dst, src)}
  % endif
% endfor
    syscall
