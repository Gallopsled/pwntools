<% from pwnlib.shellcraft.amd64 import popad %>
<%docstring>
Crash.

Example:

.. doctest::
   :skipif: not binutils_amd64 or not qemu_amd64

    >>> run_assembly(shellcraft.crash()).poll(True)
    -11
</%docstring>
    /* fill all registers with shit */
    ${popad()}
    xor rsp, rsp /* especially esp */
    jmp rsp    /* boom */
