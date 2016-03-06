<%
    from pwnlib.shellcraft import mips
    from pwnlib.shellcraft import common
%>\
<%page args="sock = '$s0'"/>
<%docstring>
Args: [sock (imm/reg) = s0]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  dup       = common.label("dup")
  looplabel = common.label("loop")
%>
${dup}:
        ${mips.mov('$a0', sock)}
        ${mips.mov('$s0', -1)}
        ${mips.mov('$a1', 2)}

${looplabel}:
        ${mips.mov('$v0', 'SYS_dup2')}
        syscall 0x42424

        addi $a1, $a1, -1
        bne $a1, $s0, ${looplabel}
