<% from pwnlib.shellcraft.thumb import mov %>
<%docstring>
Crash.

Example:

.. doctest::
   :skipif: not binutils_thumb or not qemu_thumb

    >>> run_assembly(shellcraft.crash()).poll(True) < 0
    True
</%docstring>
    pop {r0-r12,lr}
    ldr sp, [sp, 64]
    bx  r1
