<%
  from pwnlib.shellcraft import eval, common, pretty, okay, registers
  from pwnlib.log import getLogger
  from pwnlib.util import fiddling
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  import six
%>
<%page args="dst, src"/>
<%docstring>
    mov(dst, src)

    Returns THUMB code for moving the specified source value
    into the specified destination register.

    If src is a string that is not a register, then it will locally set
    `context.arch` to `'thumb'` and use :func:`pwnlib.constants.eval` to evaluate the
    string. Note that this means that this shellcode can change behavior depending
    on the value of `context.os`.

Example:

    >>> print(shellcraft.thumb.mov('r1','r2').rstrip())
        mov r1, r2
    >>> print(shellcraft.thumb.mov('r1', 0).rstrip())
        eor r1, r1
    >>> print(shellcraft.thumb.mov('r1', 10).rstrip())
        mov r1, #0xa + 1
        sub r1, r1, 1
    >>> print(shellcraft.thumb.mov('r1', 17).rstrip())
        mov r1, #0x11
    >>> print(shellcraft.thumb.mov('r1', 'r1').rstrip())
        /* moving r1 into r1, but this is a no-op */
    >>> print(shellcraft.thumb.mov('r1', 512).rstrip())
        mov r1, #0x200
    >>> print(shellcraft.thumb.mov('r1', 0x10000001).rstrip())
        mov r1, #(0x10000001 >> 28)
        lsl r1, #28
        add r1, #(0x10000001 & 0xff)
    >>> print(shellcraft.thumb.mov('r1', 0xdead0000).rstrip())
        mov r1, #(0xdead0000 >> 25)
        lsl r1, #(25 - 16)
        add r1, #((0xdead0000 >> 16) & 0xff)
        lsl r1, #16
    >>> print(shellcraft.thumb.mov('r1', 0xdead00ff).rstrip())
        ldr r1, value_...
        b value_..._after
    value_...: .word 0xdead00ff
    value_..._after:
    >>> with context.local(os = 'linux'):
    ...     print(shellcraft.thumb.mov('r1', 'SYS_execve').rstrip())
        mov r1, #SYS_execve /* 0xb */
    >>> with context.local(os = 'freebsd'):
    ...     print(shellcraft.thumb.mov('r1', 'SYS_execve').rstrip())
        mov r1, #SYS_execve /* 0x3b */
    >>> with context.local(os = 'linux'):
    ...     print(shellcraft.thumb.mov('r1', 'PROT_READ | PROT_WRITE | PROT_EXEC').rstrip())
        mov r1, #(PROT_READ | PROT_WRITE | PROT_EXEC) /* 7 */

</%docstring>
<%
log = getLogger(__name__)
src_orig = src
if isinstance(src, (six.binary_type, six.text_type)):
    src = src.strip()
    if src.lower() in registers.arm:
        src = src.lower()
    else:
        with ctx.local(arch = 'thumb'):
            try:
                src = eval(src)
            except (AttributeError, ValueError):
                log.error("Could not figure out the value of %r" % src)
                return

# ARM has a mov-const-with-shift
# As long as the const fits in 8 bits, everything works out :)
def get_imm8_shift_ok(v):
    v_bits = fiddling.bits(v)
    retval = 0

    if v == 0:
        return 1

    trailing_zeroes = v_bits[::-1].index(1)
    leading_zeroes  = v_bits.index(1)
    width           = len(v_bits) - leading_zeroes - trailing_zeroes

    if width > 8:
      return 0

    retval = v >> trailing_zeroes

    if width > 8 \
    or not okay(retval, bits=8) \
    or (width == 8 and 0 != (trailing_zeroes % 2)):
        return 0

    return retval

positive_imm8_shift = False
negative_imm8_shift = False
srcn                = None
if not src in registers.arm:
    src = eval(src)
    srcu = src & 0xffffffff
    srcn = fiddling.negate(src + 1)
    positive_imm8_shift = get_imm8_shift_ok(srcu)
    negative_imm8_shift = get_imm8_shift_ok(srcn)

%>
% if dst == src:
  /* moving ${src} into ${dst}, but this is a no-op */
% elif not isinstance(src, six.integer_types):
    mov ${dst}, ${src}
% else:
  <%
    srcu = src & 0xffffffff
    srcs = srcu - 2 * (srcu & 0x80000000)
  %>\
  %if srcu == 0:
    eor ${dst}, ${dst}
  %elif srcu == 10:
    mov ${dst}, #${pretty(src)} + 1
    sub ${dst}, ${dst}, 1
  %elif srcs == -10:
    mov ${dst}, #${pretty(src)} + 1
    sub ${dst}, ${dst}, 1
  %elif positive_imm8_shift and srcu != 10:
    mov ${dst}, #${pretty(src)}
  %elif negative_imm8_shift and srcn != 10:
    mvn ${dst}, #-${pretty(srcn)}
  %elif -256 < srcs < 0:
    eor ${dst}, ${dst}
    sub ${dst}, #${-srcs}
  %else:
    <%
      shift1 = 0
      while (1 << shift1) & src == 0:
          shift1 += 1
    %>\
    %if (0xff << shift1) & src == src:
      %if shift1 < 4:
        mov ${dst}, #(${pretty(src)} >> ${shift1})
        lsl ${dst}, #4
        lsr ${dst}, #(4 - ${shift1})
      %else:
        mov ${dst}, #(${pretty(src)} >> ${shift1})
        lsl ${dst}, #${shift1}
      %endif
    %else:
      <%
        shift2 = 8
        while (1 << shift2) & src == 0:
            shift2 += 1
      %>\
      %if ((0xff << shift2) | 0xff) & src == src:
        mov ${dst}, #(${pretty(src)} >> ${shift2})
        lsl ${dst}, #${shift2}
        add ${dst}, #(${"%#x" % src} & 0xff)
      %else:
        <%
          shift3 = shift1 + 8
          while (1 << shift3) & src == 0:
              shift3 += 1
        %>\
        %if ((0xff << shift1) | (0xff << shift3)) & src == src:
          mov ${dst}, #(${pretty(src)} >> ${shift3})
          lsl ${dst}, #(${shift3} - ${shift1})
          add ${dst}, #((${pretty(src)} >> ${shift1}) & 0xff)
          lsl ${dst}, #${shift1}
        %else:
            <%
              id = common.label("value")
              shift = False
              if (src & 0xff000000 == 0):
                  shift = True
                  src = src | 0xff000000
            %>\
            ldr ${dst}, ${id}
            b ${id}_after
            ${id}: .word ${pretty(src)}
            ${id}_after:
            %if shift:
            lsl ${dst}, #8
            lsr ${dst}, #8
            %endif
        %endif
      %endif
    %endif
  %endif
%endif
