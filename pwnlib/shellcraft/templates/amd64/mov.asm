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

    >>> print shellcraft.amd64.mov('eax','ebx').rstrip()
        mov eax, ebx
    >>> print shellcraft.amd64.mov('eax', 0).rstrip()
        xor eax, eax
    >>> print shellcraft.amd64.mov('ax', 0).rstrip()
        xor ax, ax
    >>> print shellcraft.amd64.mov('rax', 0).rstrip()
        xor eax, eax
    >>> print shellcraft.amd64.mov('al', 'ax').rstrip()
        /* moving ax into al, but this is a no-op */
    >>> print shellcraft.amd64.mov('bl', 'ax').rstrip()
        mov bl, al
    >>> print shellcraft.amd64.mov('ax', 'bl').rstrip()
        movzx ax, bl
    >>> print shellcraft.amd64.mov('eax', 1).rstrip()
        push 0x1
        pop rax
    >>> print shellcraft.amd64.mov('rax', 0xdead00ff).rstrip()
        mov eax, 0x1010101
        xor eax, 0xdfac01fe
    >>> print shellcraft.amd64.mov('rax', 0x11dead00ff).rstrip()
        mov rax, 0x101010101010101
        push rax
        mov rax, 0x1010110dfac01fe
        xor [rsp], rax
        pop rax

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
def okay(s):
    return '\0' not in s and '\n' not in s

def pretty(n):
    if n < 0:
      return str(n)
    else:
      return hex(n)

all_regs, sizes, bigger, smaller = misc.register_sizes(regs, [64, 32, 16, 8])
dest_orig = dest
%>\
% if dest not in all_regs:
    <% log.error('%s is not a register' % str(dest_orig)) %>\
% elif isinstance(src, (int, long)):
    <%
      if not (-2 ** (sizes[dest]-1) <= src < 2**sizes[dest]):
          log.error('Number %s does not fit into %s' % (pretty(src), dest_orig))

      # Calculate the unsigned and signed versions
      srcu = src & (2 ** sizes[dest] - 1)
      srcs = srcu - 2 * (srcu & (2 ** (sizes[dest] - 1)))

      # micro-optimization: if you ever touch e.g. eax, then all the upper bits
      # of rax will be set to 0. We exploit this fact here
      if 0 <= src < 2 ** 32 and sizes[dest] == 64:
          dest = smaller[dest][0]

      # Calculate the packed version
      srcp = packing.pack(srcu, sizes[dest], 'little', False)
    %>\
    % if src == 0:
        xor ${dest}, ${dest}
    % elif src == 10 and stack_allowed and sizes[dest] == 32: # sizes[dest] == 64 not possible here
        push 9
        pop ${bigger[dest][0]}
        inc ${dest}
    % elif stack_allowed and sizes[dest] in [32, 64] and -2**7 <= srcs < 2**7 and okay(srcp[0]):
        push ${pretty(srcs)}
        pop ${dest if sizes[dest] == 64 else bigger[dest][0]}
    % elif okay(srcp):
        mov ${dest}, ${pretty(src)}
    % elif stack_allowed and sizes[dest] in [32, 64] and -2**31 <= srcs < 2**31 and okay(srcp[:4]):
        push ${pretty(srcs)}
        pop ${dest if sizes[dest] == 64 else bigger[dest][0]}
    % else:
        <%
        a,b = fiddling.xor_pair(srcp, avoid = '\x00\n')
        a = pretty(packing.unpack(a, sizes[dest], 'little', False))
        b = pretty(packing.unpack(b, sizes[dest], 'little', False))
        %>\
        % if sizes[dest] != 64:
          mov ${dest}, ${a}
          xor ${dest}, ${b}
        % elif stack_allowed:
          mov ${dest}, ${a}
          push ${dest}
          mov ${dest}, ${b}
          xor [rsp], ${dest}
          pop ${dest}
        % else:
          <% log.error("Cannot put %s into '%s' without using stack." % (pretty(src), dest_orig)) %>\
        % endif
    % endif
% elif src in all_regs:
    <%
      # micro-optimization: if you ever touch e.g. eax, then all the upper bits
      # of rax will be set to 0. We exploit this fact here
      if sizes[dest] == 64 and sizes[src] != 64:
          dest = smaller[dest][0]
    %>\
    % if src == dest or src in bigger[dest] or src in smaller[dest]:
        /* moving ${src} into ${dest_orig}, but this is a no-op */
    % elif sizes[dest] == sizes[src]:
        mov ${dest}, ${src}
    % elif sizes[dest] > sizes[src]:
        movzx ${dest}, ${src}
    % else:
        % for r in smaller[src]:
            % if sizes[r] == sizes[dest]:
                mov ${dest}, ${r}
                <% break %>\
            % endif
        % endfor
    % endif
% else:
    <% log.error('%s is neither a register nor an immediate' % src) %>\
% endif
