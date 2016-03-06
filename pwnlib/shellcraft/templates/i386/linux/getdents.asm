<% from pwnlib.shellcraft import i386 %>
<%page args="in_fd = 'ebp', size = 255, allocate_stack = True"/>
<%docstring> Reads to the stack from a directory.

Args:
    in_fd (int/str): File descriptor to be read from.
    size (int): Buffer size.
    allocate_stack (bool): allocate 'size' bytes on the stack.

You can optioanlly shave a few bytes not allocating the stack space.

The size read is left in eax.
</%docstring>
  ${i386.mov('ebx', in_fd)}
  xor eax, eax
  mov al, SYS_getdents
  cdq
  ${i386.mov('dl', size)}
%if allocate_stack:
  sub esp, edx
%endif
  mov ecx, esp
  int 0x80
