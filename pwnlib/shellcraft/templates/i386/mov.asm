<% from pwnlib.util import lists, packing, fiddling, misc %>\
<%
import logging
log = logging.getLogger('pwnlib.shellcraft')
%>\
<%page args="dest, src, stack_allowed = True"/>
<%docstring>
Move src into dest without newlines and null bytes.

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

all_regs, sizes, bigger, smaller = misc.register_sizes(regs, [32, 16, 8, 8])
%>\
% if dest not in all_regs:
   <% log.error('%s is not a register' % str(dest)) %>\
% elif isinstance(src, (int, long)):
    % if src >= 2**sizes[dest] or src < -(2**(sizes[dest]-1)):
        <% log.error('Number 0x%x does not fit into %s' % (src, dest)) %>\
    % endif
    <% srcp = packing.pack(src, sizes[dest]) %>\
    % if src == 0:
        xor ${dest}, ${dest}
    % elif '\x00' not in srcp and '\n' not in srcp:
        mov ${dest}, ${hex(src)}
    % elif stack_allowed and sizes[dest] == 32 and -128 <= src <= 127 and src != 0xa:
        push ${src}
        pop ${dest}
    % elif stack_allowed and sizes[dest] == 16 and -128 <= src <= 127 and src != 0xa:
        push ${src}
        pop ${dest}
        inc esp
        inc esp
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
        % for r in bigger[dest]:
            % if sizes[r] == sizes[src]:
                mov ${r}, ${src}
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
