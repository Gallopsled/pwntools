<% from pwnlib.shellcraft import i386 %>\
<% from pwnlib.constants.linux import i386 as constants %>\
<%page args="syscall, arg0 = None, arg1 = None, arg2 = None, arg3 = None, arg4 = None"/>
<%docstring>
Args: [syscall_number, *args]
    Does a syscall
</%docstring>
% for dst, src in zip(['ebx', 'ecx', 'edx', 'esi', 'edi', 'eax'], [arg0, arg1, arg2, arg3, arg4, syscall]):
  % if src != None:
    <%
      if isinstance(src, (str, unicode)):
          src = getattr(constants, src, src)
    %>\
    ${i386.mov(dst, src)}
  % endif
% endfor
    int 0x80
