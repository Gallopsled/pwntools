<% import pwnlib.shellcraft as S %>
<%docstring>
Inserts a debugger breakpoint (raises SIGTRAP).

Example:

    >>> run_assembly(shellcraft.breakpoint()).poll(True)
    -5
</%docstring>
    brk #0
