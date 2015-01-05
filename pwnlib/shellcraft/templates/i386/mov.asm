<% from pwnlib.util import lists, packing, fiddling, misc %>\
<%
import logging
log = logging.getLogger('pwnlib.shellcraft')
%>\
<%page args="dest, src, stack_allowed = True"/>
<%docstring>
Move src into dest without newlines and null bytes.

If the src is a register smaller than the dest, then it will be
zero-extended to fit inside the larger register.

If the src is a register larger than the dest, then only some of the bits will
be used.

Example:

   >>> print shellcraft.i386.mov('eax','ebx').rstrip()
       mov eax, ebx
   >>> print shellcraft.i386.mov('eax', 0).rstrip()
       xor eax, eax
   >>> print shellcraft.i386.mov('ax', 0).rstrip()
       xor ax, ax
   >>> print shellcraft.i386.mov('ax', 17).rstrip()
       push 0x11
       pop ax
       inc esp
       inc esp
   >>> print shellcraft.i386.mov('al', 'ax').rstrip()
       /* moving ax into al, but this is a no-op */
   >>> print shellcraft.i386.mov('bl', 'ax').rstrip()
       mov bl, al
   >>> print shellcraft.i386.mov('ax', 'bl').rstrip()
       movzx ax, bl
   >>> print shellcraft.i386.mov('eax', 1).rstrip()
       push 0x1
       pop eax
   >>> print shellcraft.i386.mov('eax', 0xdead00ff).rstrip()
       mov eax, 0x1010101
       xor eax, 0xdfac01fe


Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
  stack_allowed (bool): Can the stack be used?
</%docstring>
<%
regs = [['eax', 'ax', 'al', 'ah'],
        ['ebx', 'bx', 'bl', 'bh'],
        ['ecx', 'cx', 'cl', 'ch'],
        ['edx', 'dx', 'dl', 'dh'],
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

all_regs, sizes, bigger, smaller = misc.register_sizes(regs, [32, 16, 8, 8])
%>\
% if dest not in all_regs:
   <% log.error('%s is not a register' % str(dest)) %>\
% elif isinstance(src, (int, long)):
    <%
     if src >= 2**sizes[dest] or src < -(2**(sizes[dest]-1)):
         log.error('Number 0x%x does not fit into %s' % (src, dest))

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
        mov ${dest}, ${hex(src)}
    % elif stack_allowed and sizes[dest] == 16 and -128 <= srcs <= 127 and okay(srcp[0]):
        push ${pretty(srcs)}
        pop ${dest}
        inc esp
        inc esp
    % elif stack_allowed and sizes[dest] == 32 and okay(srcp):
        push ${srcs}
        pop ${dest}
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
        <% done = False %>\
        % for r in smaller[src]:
            % if sizes[r] == sizes[dest]:
                mov ${dest}, ${r}
                <% done = True %>\
                <% break %>\
            % endif
        % endfor
        % if not done:
            <% log.error('Register %s could not be moved into %s' % (src, dest)) %>\
        % endif
    % endif
% else:
    <% log.error('%s is neither a register nor an immediate' % src) %>\
% endif
