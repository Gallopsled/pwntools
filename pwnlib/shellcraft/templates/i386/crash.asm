<%docstring>
Crash.

Example:

.. doctest::
   :skipif: not binutils_i386 or not qemu_i386

    >>> run_assembly(shellcraft.crash()).poll(True)
    -11
</%docstring>
    popad        /* fill all registers with shit */
    xor esp, esp /* especially esp */
    jmp esp      /* boom */
