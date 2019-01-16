<%
  from pwnlib.util import lists, packing, fiddling, misc
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  from pwnlib.shellcraft import eval, pretty, okay
  from pwnlib.shellcraft.registers import get_register, is_register, bits_required
  import six
  log = getLogger('pwnlib.shellcraft.amd64.mov')
%>
<%page args="dest, src, stack_allowed = True"/>
<%docstring>
Move src into dest without newlines and null bytes.

If the src is a register smaller than the dest, then it will be
zero-extended to fit inside the larger register.

If the src is a register larger than the dest, then only some of the bits will
be used.

If src is a string that is not a register, then it will locally set
`context.arch` to `'amd64'` and use :func:`pwnlib.constants.eval` to evaluate the
string. Note that this means that this shellcode can change behavior depending
on the value of `context.os`.

Example:

    >>> print(shellcraft.amd64.mov('eax','ebx').rstrip())
        mov eax, ebx
    >>> print(shellcraft.amd64.mov('eax', 0).rstrip())
        xor eax, eax /* 0 */
    >>> print(shellcraft.amd64.mov('ax', 0).rstrip())
        xor ax, ax /* 0 */
    >>> print(shellcraft.amd64.mov('rax', 0).rstrip())
        xor eax, eax /* 0 */
    >>> print(shellcraft.amd64.mov('rdi', 'ax').rstrip())
        movzx edi, ax
    >>> print(shellcraft.amd64.mov('al', 'ax').rstrip())
        /* moving ax into al, but this is a no-op */
    >>> print(shellcraft.amd64.mov('ax', 'bl').rstrip())
        movzx ax, bl
    >>> print(shellcraft.amd64.mov('eax', 1).rstrip())
        push 1
        pop rax
    >>> print(shellcraft.amd64.mov('rax', 0xc0).rstrip())
        xor eax, eax
        mov al, 0xc0
    >>> print(shellcraft.amd64.mov('rax', 0xc000).rstrip())
        xor eax, eax
        mov ah, 0xc000 >> 8
    >>> print(shellcraft.amd64.mov('rax', 0xc0c0).rstrip())
        xor eax, eax
        mov ax, 0xc0c0
    >>> print(shellcraft.amd64.mov('rdi', 0xff).rstrip())
        mov edi, 0x1010101 /* 255 == 0xff */
        xor edi, 0x10101fe
    >>> print(shellcraft.amd64.mov('rax', 0xdead00ff).rstrip())
        mov eax, 0x1010101 /* 3735879935 == 0xdead00ff */
        xor eax, 0xdfac01fe
    >>> print(shellcraft.amd64.mov('rax', 0x11dead00ff).rstrip())
        mov rax, 0x101010101010101 /* 76750323967 == 0x11dead00ff */
        push rax
        mov rax, 0x1010110dfac01fe
        xor [rsp], rax
        pop rax
    >>> print(shellcraft.amd64.mov('rax', 0xffffffff).rstrip())
        mov eax, 0xffffffff
    >>> print(shellcraft.amd64.mov('rax', 0x7fffffff).rstrip())
        mov eax, 0x7fffffff
    >>> print(shellcraft.amd64.mov('rax', 0x80010101).rstrip())
        mov eax, 0x80010101
    >>> print(shellcraft.amd64.mov('rax', 0x80000000).rstrip())
        mov eax, 0x1010101 /* 2147483648 == 0x80000000 */
        xor eax, 0x81010101
    >>> print(shellcraft.amd64.mov('rax', 0xffffffffffffffff).rstrip())
        push 0xffffffffffffffff
        pop rax
    >>> with context.local(os = 'linux'):
    ...     print(shellcraft.amd64.mov('eax', 'SYS_read').rstrip())
        xor eax, eax /* SYS_read */
    >>> with context.local(os = 'freebsd'):
    ...     print(shellcraft.amd64.mov('eax', 'SYS_read').rstrip())
        push SYS_read /* 3 */
        pop rax
    >>> with context.local(os = 'linux'):
    ...     print(shellcraft.amd64.mov('eax', 'PROT_READ | PROT_WRITE | PROT_EXEC').rstrip())
        push (PROT_READ | PROT_WRITE | PROT_EXEC) /* 7 */
        pop rax

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
  stack_allowed (bool): Can the stack be used?
</%docstring>
<%
if not get_register(dest):
    log.error('%r is not a register' % dest)

dest = get_register(dest)

if get_register(src):
    src = get_register(src)

    if dest.size < src.size and src.name not in dest.bigger:
        log.error("cannot mov %s, %s: dddest is smaller than src" % (dest, src))

    # Can't move between RAX and DIL for example.
    if dest.rex_mode & src.rex_mode == 0:
        log.error('The amd64 instruction set does not support moving from %s to %s' % (src, dest))

    # Downgrade our register choice if possible.
    # Opcodes for operating on 32-bit registers are always (?) shorter.
    if dest.size == 64 and src.size <= 32:
        dest = get_register(dest.native32)

else:
    with ctx.local(arch = 'amd64'):
        src = eval(src)

    if not dest.fits(src):
        log.error("cannot mov %s, %r: dest is smaller than src" % (dest, src))

    orig_dest = dest

    if dest.size == 64 and bits_required(src) <= 32:
        dest = get_register(dest.native32)

    # Calculate the packed version
    srcp = packing.pack(src & ((1<<dest.size)-1), dest.size)

    # Calculate the unsigned and signed versions
    srcu = packing.unpack(srcp, dest.size, sign=False)

    # N.B.: We may have downsized the register for e.g. mov('rax', 0xffffffff)
    #       In this case, srcp is now a 4-byte packed value, which will expand
    #       to "-1", which isn't correct.
    if orig_dest.size != dest.size:
        srcs = src
    else:
        srcs = packing.unpack(srcp, dest.size, sign=True)

%>\
% if is_register(src):
    % if src == dest:
    /* moving ${src} into ${dest}, but this is a no-op */
    % elif src.name in dest.bigger:
    /* moving ${src} into ${dest}, but this is a no-op */
    % elif dest.size > src.size:
    movzx ${dest}, ${src}
    % else:
    mov ${dest}, ${src}
    % endif
% elif isinstance(src, six.integer_types):
## Special case for zeroes
## XORing the 32-bit register clears the high 32 bits as well
    % if src == 0:
        xor ${dest}, ${dest} /* ${src} */
## Special case for *just* a newline
    % elif stack_allowed and dest.size in (32,64) and src == 10:
        push 9 /* mov ${dest}, '\n' */
        pop ${dest.native64}
        inc ${dest}
## It's smaller to PUSH and POP small sign-extended values
## than to directly move them into various registers,
##
## 6aff58           push -1; pop rax
## 48c7c0ffffffff   mov rax, -1
    % elif stack_allowed and dest.size in (32,64) and (-2**7 <= srcs < 2**7) and okay(srcp[:1]):
        push ${pretty(src)}
        pop ${dest.native64}
## Easy case, everybody is trivially happy
## This implies that the register size and value are the same.
    % elif okay(srcp):
        mov ${dest}, ${pretty(src)}
## We can push 32-bit values onto the stack and they are sign-extended.
    % elif stack_allowed and dest.size in (32,64) and (-2**31 <= srcs < 2**31) and okay(srcp[:4]):
        push ${pretty(src)}
        pop ${dest.native64}
## We can also leverage the sign-extension to our advantage.
## For example, 0xdeadbeef is sign-extended to 0xffffffffdeadbeef.
## Want EAX=0xdeadbeef, we don't care that RAX=0xfff...deadbeef.
    % elif stack_allowed and dest.size == 32 and srcu < 2**32 and okay(srcp[:4]):
        push ${pretty(src)}
        pop ${dest.native64}
## Target value is an 8-bit value, use a 8-bit mov
    % elif srcu < 2**8 and okay(srcp[:1]) and 8 in dest.sizes:
        xor ${dest.xor}, ${dest.xor}
        mov ${dest.sizes[8]}, ${pretty(src)}
## Target value is a 16-bit value with no data in the low 8 bits
## means we can use the 'AH' style register.
    % elif srcu == srcu & 0xff00 and okay(srcp[1:2]) and dest.ff00:
        xor ${dest}, ${dest}
        mov ${dest.ff00}, ${pretty(src)} >> 8
## Target value is a 16-bit value, use a 16-bit mov
    % elif srcu < 2**16 and okay(srcp[:2]):
        xor ${dest.xor}, ${dest.xor}
        mov ${dest.sizes[16]}, ${pretty(src)}
## Target value is a 32-bit value, use a 32-bit mov.
## Note that this is zero-extended rather than sign-extended (the 32-bit push above).
    % elif srcu < 2**32 and okay(srcp[:4]):
        mov ${dest.sizes[32]}, ${pretty(src)}
## All else has failed.  Use some XOR magic to move things around.
    % else:
        <%
        a,b = fiddling.xor_pair(srcp, avoid = b'\x00\n')
        a = '%#x' % packing.unpack(a, dest.size)
        b = '%#x' % packing.unpack(b, dest.size)
        %>\
## There's no XOR REG, IMM64 but we can take the easy route
## for smaller registers.
        % if dest.size != 64:
        mov ${dest}, ${a} /* ${str(src)} == ${"%#x" % (src)} */
        xor ${dest}, ${b}
## However, we can PUSH IMM64 and then perform the XOR that
## way at the top of the stack.
        % elif stack_allowed:
        mov ${dest}, ${a} /* ${str(src)} == ${"%#x" % (src)} */
        push ${dest}
        mov ${dest}, ${b}
        xor [rsp], ${dest}
        pop ${dest}
        % else:
            <% log.error("Cannot put %s into '%s' without using stack." % (pretty(src), orig_dest)) %>\
        % endif
    % endif
% else:
    <% log.error('%s is neither a register nor an immediate' % src) %>\
% endif
