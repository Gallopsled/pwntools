<%
  from pwnlib.util import lists, packing, fiddling, misc
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  from pwnlib.log import getLogger
  log = getLogger('pwnlib.shellcraft.i386.mov')
%>
<%page args="dest, src, stack_allowed = True"/>
<%docstring>
Move src into dest without newlines and null bytes.

If the src is a register smaller than the dest, then it will be
zero-extended to fit inside the larger register.

If src is a string that is not a register, then it will locally set
`context.arch` to `'i386'` and use :func:`pwnlib.constants.eval` to evaluate the
string. Note that this means that this shellcode can change behavior depending
on the value of `context.os`.

Example:

    >>> print shellcraft.i386.mov('eax','ebx').rstrip()
        mov eax, ebx
    >>> print shellcraft.i386.mov('eax', 0).rstrip()
        xor eax, eax
    >>> print shellcraft.i386.mov('ax', 0).rstrip()
        xor ax, ax
    >>> print shellcraft.i386.mov('ax', 17).rstrip()
        xor ax, ax
        mov al, 0x11
    >>> print shellcraft.i386.mov('al', 'ax').rstrip()
        /* moving ax into al, but this is a no-op */
    >>> print shellcraft.i386.mov('ax', 'bl').rstrip()
        movzx ax, bl
    >>> print shellcraft.i386.mov('eax', 1).rstrip()
        push 0x1
        pop eax
    >>> print shellcraft.i386.mov('eax', 0xdead00ff).rstrip()
        mov eax, 0x1010101
        xor eax, 0xdfac01fe
    >>> print shellcraft.i386.mov('eax', 0xc0).rstrip()
        xor eax, eax
        mov al, 0xc0
    >>> print shellcraft.i386.mov('eax', 0xc000).rstrip()
        xor eax, eax
        mov ah, 0xc0
    >>> print shellcraft.i386.mov('eax', 0xc0c0).rstrip()
        xor eax, eax
        mov ax, 0xc0c0
    >>> print shellcraft.i386.mov('edi', 0x300).rstrip()
        mov edi, 0x1010101
        xor edi, 0x1010201
    >>> print shellcraft.i386.mov('di', 0x301).rstrip()
        mov di, 0x301
    >>> with context.local(os = 'linux'):
    ...     print shellcraft.i386.mov('eax', 'SYS_execve').rstrip()
        push 0xb
        pop eax
    >>> with context.local(os = 'freebsd'):
    ...     print shellcraft.i386.mov('eax', 'SYS_execve').rstrip()
        push 0x3b
        pop eax
    >>> with context.local(os = 'linux'):
    ...     print shellcraft.i386.mov('eax', 'PROT_READ | PROT_WRITE | PROT_EXEC').rstrip()
        push 0x7
        pop eax

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
  stack_allowed (bool): Can the stack be used?
</%docstring>
<%
regs = [['eax', 'ax', 'ah', 'al'],
        ['ebx', 'bx', 'bh', 'bl'],
        ['ecx', 'cx', 'ch', 'cl'],
        ['edx', 'dx', 'dh', 'dl'],
        ['edi', 'di'],
        ['esi', 'si'],
        ['ebp', 'bp'],
        ['esp', 'sp'],
        ]

def okay(s):
    return '\0' not in s and '\n' not in s

def pretty(n):
    if n < 0:
        return str(n)
    else:
        return hex(n)

def regular(reg):
    return reg in ['eax','ebx','ecx','edx', 'ax', 'bx', 'cx', 'dx']

all_regs, sizes, bigger, smaller = misc.register_sizes(regs, [32, 16, 8, 8])

if isinstance(src, (str, unicode)):
    src = src.strip()
    if src.lower() in all_regs:
        src = src.lower()
    else:
        with ctx.local(arch = 'i386'):
            try:
                src = constants.eval(src)
            except (AttributeError, ValueError):
                log.error("Could not figure out the value of %r" % src)
                return
%>
% if dest not in all_regs:
   <% log.error('%s is not a register' % str(dest)) %>\
% elif isinstance(src, (int, long)):
    <%
     if src >= 2**sizes[dest] or src < -(2**(sizes[dest]-1)):
         log.error('Number 0x%x does not fit into %s' % (src, dest))
         return

     # Calculate the unsigned and signed versions
     srcu = src & (2 ** sizes[dest] - 1)
     srcs = srcu - 2 * (srcu & (2 ** (sizes[dest] - 1)))

     # Calculate the packed version
     srcp = packing.pack(srcu, sizes[dest], 'little', False)
    %>\
    % if src == 0:
        xor ${dest}, ${dest}
    % elif src == 10 and stack_allowed and sizes[dest] == 32:
        push 9
        pop ${bigger[dest][0]}
        inc ${dest}
    % elif stack_allowed and sizes[dest] == 32 and -128 <= srcs <= 127 and okay(srcp[0]):
        push ${pretty(srcs)}
        pop ${dest}
    % elif okay(srcp):
        mov ${dest}, ${pretty(src)}
    % elif regular(dest) and 0 <= srcu < 2**8 and okay(srcp[0]) and sizes[smaller[dest][-1]] == 8:
        xor ${dest}, ${dest}
        mov ${smaller[dest][-1]}, ${pretty(srcu)}
    % elif regular(dest) and srcu == srcu & 0xff00 and okay(srcp[1]) and sizes[smaller[dest][-2]] == 8:
        xor ${dest}, ${dest}
        mov ${smaller[dest][-2]}, ${pretty(srcu >> 8)}
    % elif 0 <= srcu < 2**16 and okay(srcp[:2]) and (dest in ['di', 'si','bp', 'sp'] or sizes[smaller[dest][0]] == 16):
        xor ${dest}, ${dest}
        mov ${smaller[dest][0]}, ${pretty(src)}
    % else:
        <%
        a,b = fiddling.xor_pair(srcp, avoid = '\x00\n')
        a = hex(packing.unpack(a, sizes[dest]))
        b = hex(packing.unpack(b, sizes[dest]))
        %>\
        mov ${dest}, ${a}
        xor ${dest}, ${b}
    % endif
% elif src in all_regs:
    % if src == dest or src in bigger[dest] or src in smaller[dest]:
        /* moving ${src} into ${dest}, but this is a no-op */
    % elif sizes[dest] == sizes[src]:
        mov ${dest}, ${src}
    % elif sizes[dest] > sizes[src]:
        movzx ${dest}, ${src}
    % else:
        <% log.error('Register %s could not be moved into %s' % (src, dest)) %>\
    % endif
% else:
    <% log.error('%s is neither a register nor an immediate' % src) %>\
% endif
