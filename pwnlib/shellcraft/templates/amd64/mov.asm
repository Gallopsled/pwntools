<% from pwnlib.util import lists, packing, fiddling, misc %>
<%
import logging
log = logging.getLogger('pwnlib.shellcraft')
%>

<%page args="dest, src, stack_allowed = True"/>
<%docstring>
Move src into dest without newlines and null bytes.

Args:
  dest (str): The destination register.
  src (str): Either the input register, or an immediate value.
  stack_allowed (bool): Can the stack be used?
</%docstring>

<%
regs = [['rax', 'eax', 'ax', 'al'],
        ['rbx', 'ebx', 'bx', 'bl'],
        ['rcx', 'ecx', 'cx', 'cl'],
        ['rdx', 'edx', 'dx', 'dl'],
        ['rdi', 'edi', 'di', 'dil'],
        ['rsi', 'esi', 'si', 'sil'],
        ['rbp', 'ebp', 'bp', 'bpl'],
        ['rsp', 'esp', 'sp', 'spl'],
        ['r8', 'r8d', 'r8w', 'r8b'],
        ['r9', 'r9d', 'r9w', 'r9b'],
        ['r10', 'r10d', 'r10w', 'r10b'],
        ['r11', 'r11d', 'r11w', 'r11b'],
        ['r12', 'r12d', 'r12w', 'r12b'],
        ['r13', 'r13d', 'r13w', 'r13b'],
        ['r14', 'r14d', 'r14w', 'r14b'],
        ['r15', 'r15d', 'r15w', 'r15b']
        ]

all_regs, sizes, bigger, smaller = misc.register_sizes(regs, [64, 32, 16, 8, 8])
%>

% if dest not in all_regs:
    <% log.error('%s is not a register' % str(dest)) %>
% endif

% if isinstance(src, (int, long)):
    % if src >= 2**sizes[dest] or src < -(2**(sizes[dest]-1)):
        <% log.error('Number 0x%x does not fit into %s' % (src, dest)) %>
    % endif

    <% srcp = packing.pack(src, sizes[dest]) %>

    % if src == 0:
        % if sizes[dest] == 64:
            xor ${smaller[dest][0]}, ${smaller[dest][0]}
        % else:
            xor ${dest}, ${dest}
        % endif

    % elif '\x00' not in srcp and '\n' not in srcp:
        mov ${dest}, ${hex(src)}

    % elif stack_allowed and sizes[dest] == 64 and -128 <= src <= 127 and src != 0xa:
        push ${hex(src)}
        pop ${dest}

    % elif stack_allowed and sizes[dest] == 32 and -128 <= src <= 127 and src != 0xa:
        push ${hex(src)}
        pop ${bigger[dest][0]}

    % else:
        <%
        a,b = fiddling.xor_pair(srcp, avoid = '\x00\n')
        a = hex(packing.unpack(a, sizes[dest]))
        b = hex(packing.unpack(b, sizes[dest]))
        %>
        mov ${dest}, ${a}
        xor ${dest}, ${b}
    % endif

% elif src in all_regs:
    % if src == dest or src in bigger[dest] or src in smaller[dest]:
        /* Trivial case */
    % elif sizes[dest] == sizes[src]:
        mov ${dest}, ${src}
    elif sizes[dest] == 64 and sizes[src] == 32:
        mov ${smaller[dest][0]}, ${src}
    elif sizes[dest] > sizes[src]:
        movzx ${dest}, ${src}
    % else:
        <% done = False %>
        % for r in bigger[dest]:
            % if sizes[r] == sizes[src]:
                mov ${r}, ${src}
                <% done = True %>
                <% break %>
            % endif
        % endfor
        % if not done:
            <% log.error('Register %s could not be moved into %s' % (src, dest)) %>
        % endif
    % endif

% else:
    <% log.error('%s is neither a register nor an immediate' % src) %>
% endif
