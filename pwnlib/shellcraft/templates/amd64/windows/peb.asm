<% from pwnlib.shellcraft import amd64 %>
<%docstring>Loads the Process Environment Block (PEB) into the target register.

Args:
    dest (str): The register to load the PEB into.
</%docstring>
<%page args="dest='rax'"/>
    ${amd64.windows.teb(dest, 0x60)}
