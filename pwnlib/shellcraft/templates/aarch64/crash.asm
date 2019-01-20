<% import pwnlib.shellcraft as S %>
<%docstring>
Crashes the process.

Example:

.. doctest::
   :skipif: not binutils_aarch64 or not qemu_aarch64

    >>> run_assembly(shellcraft.crash()).poll(True)
    -11
</%docstring>
    ${S.mov('x30', 0)}
    ret
