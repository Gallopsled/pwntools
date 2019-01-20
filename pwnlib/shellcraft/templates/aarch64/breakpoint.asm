<% import pwnlib.shellcraft as S %>
<%docstring>
Inserts a debugger breakpoint (raises SIGTRAP).

Example:

.. doctest::
   :skipif: not binutils_aarch64 or not qemu_aarch64

    >>> run_assembly(shellcraft.breakpoint()).poll(True)
    -5
</%docstring>
    brk #0
