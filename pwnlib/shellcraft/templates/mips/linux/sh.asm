<% from pwnlib.shellcraft import mips %>
<%docstring>Execute /bin/sh

Example:

    >>> print enhex(asm(shellcraft.mips.sh()))
    6269093c2f2f2935f4ffa9af7368093c6e2f2935f8ffa9affcffa0aff4ffbd272020a003fcffa0affcffbd27ffff0628fcffa6affcffbd232030a00373680934fcffa9affcffbd27ffff0528fcffa5affcffbd23fbff1924272820032028bd00fcffa5affcffbd232028a003ab0f02340c010101
</%docstring>

${mips.execve('//bin/sh', ['sh'], {})}
