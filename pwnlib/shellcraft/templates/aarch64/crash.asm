<% import pwnlib.shellcraft as S %>
<%docstring>
Crashes the process.

Example:

    >>> run_assembly(shellcraft.crash()).poll(True)
    -11
</%docstring>
    ${S.mov('x30', 0)}
    ret
