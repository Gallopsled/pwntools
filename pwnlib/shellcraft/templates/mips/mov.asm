<%
  from pwnlib.util import lists, packing, fiddling, misc
  from pwnlib.constants import eval, Constant
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.shellcraft import mips, registers, pretty, okay
  log = getLogger('pwnlib.shellcraft.mips.mov')
%>
<%page args="dst, src"/>
<%docstring>
Move src into dst without newlines and null bytes.

Register $t8 and $t9 are not guarenteed to be preserved.

If src is a string that is not a register, then it will locally set
`context.arch` to `'mips'` and use :func:`pwnlib.constants.eval` to evaluate the
string. Note that this means that this shellcode can change behavior depending
on the value of `context.os`.

Args:

  dst (str): The destination register.
  src (str): Either the input register, or an immediate value.

Example:

    >>> print shellcraft.mips.mov('$t0', 0).rstrip()
        slti $t0, $zero, 0xFFFF /* $t0 = 0 */
    >>> print shellcraft.mips.mov('$t2', 0).rstrip()
        xor $t2, $t2, $t2  /* $t2 = 0 */
    >>> print shellcraft.mips.mov('$t0', 0xcafebabe).rstrip()
        li $t0, 0xcafebabe
    >>> print shellcraft.mips.mov('$t2', 0xcafebabe).rstrip()
        li $t9, 0xcafebabe
        add $t2, $t9, $zero
    >>> print shellcraft.mips.mov('$s0', 0xca0000be).rstrip()
        li $t9, ~0xca0000be
        not $s0, $t9
    >>> print shellcraft.mips.mov('$s0', 0xca0000ff).rstrip()
        li $t9, 0x1010101 ^ 0xca0000ff
        li $s0, 0x1010101
        xor $s0, $t9, $s0
    >>> print shellcraft.mips.mov('$t9', 0xca0000be).rstrip()
        li $t9, ~0xca0000be
        not $t9, $t9
    >>> print shellcraft.mips.mov('$t2', 0xca0000be).rstrip()
        li $t9, ~0xca0000be
        not $t9, $t9
        add $t2, $t9, $0 /* mov $t2, $t9 */
    >>> print shellcraft.mips.mov('$t2', 0xca0000ff).rstrip()
        li $t8, 0x1010101 ^ 0xca0000ff
        li $t9, 0x1010101
        xor $t9, $t8, $t9
        add $t2, $t9, $0 /* mov $t2, $t9 */
    >>> print shellcraft.mips.mov('$a0', '$t2').rstrip()
        add $a0, $t2, $0 /* mov $a0, $t2 */
    >>> print shellcraft.mips.mov('$a0', '$t8').rstrip()
        sw $t8, -4($sp) /* mov $a0, $t8 */
        lw $a0, -4($sp)

</%docstring>
<%
if isinstance(src, str) and src.startswith('$') and src not in registers.mips:
    log.error("Unknown register %r" % src)
    return

if not dst.startswith('$'):
    log.error("Registers must start with $")
    return

if isinstance(src, str) and dst.startswith('$') and dst not in registers.mips:
    log.error("Unknown register %r" % dst)
    return

if isinstance(src, str) and src not in registers.mips:
    src = eval(src)

src_reg = registers.mips.get(src, None)
dst_reg = registers.mips.get(dst, None)
tmp_reg = '$t9' if dst_reg != registers.mips['$t9'] else '$t8'

if src_reg == 0:
    src = 0
    src_reg = None
%>\
% if None not in (src_reg, dst_reg):
    % if src_reg == dst_reg:
## Nop.
    /* mov ${dst}, ${src} is a noop */
    % elif src_reg not in [2, 3, 4, 5, 6, 7, 8, 16, 24]:
## Avoid using a src in the list because it causes NULL byte
    add ${dst}, ${src}, $0 /* mov ${dst}, ${src} */
    % else:
## Better than two 'li' instructions due to being two instructions
## fewer. 'li' is actually 'lui' and 'ori' in hiding.
    sw ${src}, -4($sp) /* mov ${dst}, ${src} */
    lw ${dst}, -4($sp)
    % endif
% elif dst_reg == 10:
## Register $t2/$10 may encodes a newline for 'lui $t2, XXXX'
## so we have to send everything through $t9.
    %if okay(src):
    li $t9, ${pretty(src)}
    add ${dst}, $t9, $zero
    % elif src in (0, '$zero', '$0'):
    xor ${dst}, ${dst}, ${dst}  /* ${dst} = 0 */
    % elif dst == '$t2':
    ${mips.mov('$t9', src)}
    ${mips.mov(dst, '$t9')}
    %endif
% elif isinstance(src, (int, long)):
## Everything else is the general case for moving into registers.
<%
    srcp = packing.pack(src, word_size=32)
    srcu = packing.unpack(srcp, word_size=32, sign=False)
%>
% if src in (0, '$zero', '$0'):
## XOR sometimes encodes a zero byte, so use SLTI instead
    slti ${dst}, $zero, 0xFFFF /* ${dst} = 0 */
% elif okay(src):
## Nice and easy
    li ${dst}, ${pretty(src)}
% elif 0 < src <= 0xffff and okay(src, bytes=2):
    ori ${dst}, $zero, ${src}
% elif okay((~srcu) & 0xffffffff):
## Almost nice and easy
    li $t9, ~${pretty(src)}
    not ${dst}, $t9
% else:
<%
a,b = fiddling.xor_pair(srcp, avoid = '\x00\n')
a = hex(packing.unpack(a, 32))
b = hex(packing.unpack(b, 32))
%>
    li ${tmp_reg}, ${a} ^ ${pretty(src)}
    li ${dst}, ${a}
    xor ${dst}, ${tmp_reg}, ${dst}
% endif
% endif
