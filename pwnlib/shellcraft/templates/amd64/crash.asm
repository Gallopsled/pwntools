<% from pwnlib.shellcraft.amd64 import popad %>
<%docstring>
Crash.

Example:

    >>> run_assembly(shellcraft.crash()).poll(True)
    -11
</%docstring>
    /* fill all registers with shit */
    ${popad()}
    xor rsp, rsp /* especially esp */
    jmp rsp    /* boom */
