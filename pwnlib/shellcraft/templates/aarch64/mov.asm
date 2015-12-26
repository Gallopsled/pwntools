<%
  from pwnlib.shellcraft import common, aarch64
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.util.lists import group
  from pwnlib.util.packing import p16, u16, pack, unpack
  from pwnlib.util.fiddling import xor_pair
  from pwnlib.shellcraft import pretty
  from pwnlib.shellcraft.registers import aarch64 as regs
  log = getLogger('pwnlib.shellcraft.arm.mov')
%>
<%page args="dst, src"/>
<%docstring>
Move src into dest.

Support for automatically avoiding newline and null bytes has to be done.

If src is a string that is not a register, then it will locally set
`context.arch` to `'arm'` and use :func:`pwnlib.constants.eval` to evaluate the
string. Note that this means that this shellcode can change behavior depending
on the value of `context.os`.

Examples:

    >>> print shellcraft.aarch64.mov('x0','x1').rstrip()
        mov  x0, x1
    >>> print shellcraft.aarch64.mov('x0','0').rstrip()
        mov  x0, xzr
    >>> print shellcraft.aarch64.mov('x0', 5).rstrip()
        mov  x0, #5
    >>> print shellcraft.aarch64.mov('x0', 0x34532).rstrip()
        /* Set x0 = 214322 = 0x34532 */
        mov  x0, #17714
        movk x0, #3, lsl #16

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
</%docstring>
<%
if dst not in regs:
    log.error('%r is not a register' % str(dst))

if not src in regs:
    with ctx.local(arch = 'aarch64'):
        src = constants.eval(src)

mov_x0_x15 = False
xor        = None

# if isinstance(src, (int, long)):
#     # Moving an immediate into x0 emits a null byte.
#     # Moving a register into x0 does not.
#     # Use x15 as a scratch register.
#     if dst == 'x0':
#         mov_x0_x15 = True
#         dst = 'x15'
#
#     packed = pack(src)
#     words  = group(2, packed)
#     xor    = ['\x00\x00'] * 4
#     okay   = False
#
#     for i, word in enumerate(list(words)):
#         # If an entire word is zero, we can work around it.
#         # However, if any of the individual bytes are '\n', or only
#         # one of the bytes is a zero, we must do an XOR.
#         if '\n' not in word or word == '\x00\x00' or '\x00' not in word:
#             continue
#
#         a, b = xor_pair(word)
#         words[i] = a
#         xor[i]   = b
#
#     src = unpack(''.join(words))
#     xor = unpack(''.join(xor))

%>
%if not isinstance(src, (int, long)):
    mov  ${dst}, ${src}
%else:
  %if src == 0:
    mov  ${dst}, xzr
  %elif src & 0xffff == 0:
    eor  ${dst}, ${dst}, ${dst}
  %elif src & 0xffff == src:
    mov  ${dst}, #${src}
  %else:
    /* Set ${dst} = ${src} = ${pretty(src)} */
    %if src & 0x000000000000ffff:
    mov  ${dst}, #${(src >> 0x00) & 0xffff}
    %endif
    %if src & 0x00000000ffff0000:
    movk ${dst}, #${(src >> 0x10) & 0xffff}, lsl #16
    %endif
    %if src & 0x0000ffff00000000:
    movk ${dst}, #${(src >> 0x20) & 0xffff}, lsl #0x20
    %endif
    %if src & 0xffff000000000000:
    movk ${dst}, #${(src >> 0x30) & 0xffff}, lsl #0x30
    %endif
    %if xor:
    ${aarch64.mov('x14', xor)}
    eor ${dst}, ${dst}, x14
    %endif
    %if mov_x0_x15:
    ${aarch64.mov('x0','x15')}
    %endif
  %endif
%endif
