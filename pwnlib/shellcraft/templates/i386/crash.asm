<%docstring>
Crash.

Example:

    >>> run_assembly(shellcraft.crash()).poll(True)
    -11
</%docstring>
    popad        /* fill all registers with shit */
    xor esp, esp /* especially esp */
    jmp esp      /* boom */
