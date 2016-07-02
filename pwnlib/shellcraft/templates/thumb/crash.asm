<% from pwnlib.shellcraft.thumb import mov %>
<%docstring>
Crash.

Example:

    >>> run_assembly(shellcraft.crash()).poll(True) < 0
    True
</%docstring>
    pop {r0-r12,lr}
    ldr sp, [sp, 64]
    bx  r1
