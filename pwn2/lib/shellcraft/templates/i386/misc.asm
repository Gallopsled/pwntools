<%def name="nop()">
<%docstring>A single-byte nop instruction.</%docstring>
    nop
</%def>
<%def name="breakpoint()">
<%docstring>A single-byte breakpoint instruction.</%docstring>
    int3
</%def>
<%def name="infloop()">
<%docstring>A two-byte infinite loop.</%docstring>
    jmp $
</%def>
