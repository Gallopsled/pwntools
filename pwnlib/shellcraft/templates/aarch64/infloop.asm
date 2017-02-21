<% from pwnlib.shellcraft import common %>
<%docstring>
An infinite loop.

Example:

    >>> io = run_assembly(shellcraft.breakpoint())
    >>> io.recvall(timeout=1)
    ''
    >>> io.close()

</%docstring>
<% infloop = common.label("infloop") %>
${infloop}:
    b ${infloop}
