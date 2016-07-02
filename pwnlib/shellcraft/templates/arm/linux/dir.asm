<% from pwnlib.shellcraft import arm, pretty, common %>
<%page args="in_fd = 'r6', size = 0x800, allocate_stack = True"/>
<%docstring> Reads to the stack from a directory.

Args:
    in_fd (int/str): File descriptor to be read from.
    size (int): Buffer size.
    allocate_stack (bool): allocate 'size' bytes on the stack.

You can optioanlly shave a few bytes not allocating the stack space.

The size read is left in eax.
</%docstring>
<%
    getdents_loop = common.label('getdents_loop')
%>
%if allocate_stack:
    sub sp, sp, ${pretty(size)}
%endif
${getdents_loop}:
    ${arm.linux.getdents(in_fd, 'sp', size)}
