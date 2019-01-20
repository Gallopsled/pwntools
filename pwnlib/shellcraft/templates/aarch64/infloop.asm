<% from pwnlib.shellcraft import common %>
<%docstring>
An infinite loop.

Example:

.. doctest::
   :skipif: not binutils_aarch64 or not qemu_aarch64

    >>> io = run_assembly(shellcraft.infloop())
    >>> io.recvall(timeout=1)
    ''
    >>> io.close()

</%docstring>
<% infloop = common.label("infloop") %>
${infloop}:
    b ${infloop}
