<% from pwnlib.shellcraft.arm import mov %>
<%docstring>
Crash.

Example:

    >>> run_assembly(shellcraft.crash()).poll(True)
    -11
</%docstring>
    pop {r0-r12,lr}
    ${mov('sp', 0)}
    add pc, sp, #0
