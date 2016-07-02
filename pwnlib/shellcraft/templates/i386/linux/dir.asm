<% from pwnlib.shellcraft import i386, pretty %>
<%page args="in_fd = 'ebp', size = 0x800, allocate_stack = True"/>
<%docstring> Reads to the stack from a directory.

Args:
    in_fd (int/str): File descriptor to be read from.
    size (int): Buffer size.
    allocate_stack (bool): allocate 'size' bytes on the stack.

You can optioanlly shave a few bytes not allocating the stack space.

The size read is left in eax.
</%docstring>
%if allocate_stack:
  sub esp, ${pretty(size)}
%endif
  ${i386.linux.getdents(in_fd, 'esp', size)}
