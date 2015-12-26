<%
  from pwnlib.shellcraft import pretty, common, aarch64, registers
  from pwnlib.shellcraft.registers import aarch64 as regs
  from pwnlib.util.packing import pack, unpack
  from pwnlib.context import context as ctx
  from pwnlib.log import getLogger
%>
<%page args="key, address, count"/>
<%docstring>
XORs data a constant value.

Args:
    key (int,str): XOR key either as a 4-byte integer,
                   If a string, length must be a power of two,
                   and not longer than 4 bytes.
    address (int): Address of the data (e.g. 0xdead0000, 'rsp')
    count (int): Number of bytes to XOR.

Example:

    >>> sc  = shellcraft.read(0, 'sp', 32)
    >>> sc += shellcraft.xor(0xdeadbeef, 'sp', 32)
    >>> sc += shellcraft.write(1, 'sp', 32)
    >>> io = run_assembly(sc)
    >>> io.send(cyclic(32))
    >>> result = io.recvn(32)
    >>> expected = xor(cyclic(32), p32(0xdeadbeef))
    >>> result == expected
    True
</%docstring>
<%
log = getLogger('pwnlib.shellcraft.templates.aarch64.xor')

# By default, assume the key is a register
key_size   = ctx.bytes
key_pretty = key

if not key in regs:
    key_str = key
    key_int = key

    if isinstance(key, int):
        key_str = pack(key, bytes=4)
    else:
        key_int = unpack(key, 'all')

    if len(key_str) > ctx.bytes:
        log.error("Key %s is too large (max %i bytes)" % (pretty(key), ctx.bytes))

    if len(key_str) not in (1,2,4):
        log.error("Key length must be a power of two (got %s)" % pretty(key))

    key_size = len(key_str)
    key_pretty = pretty(key_int)

if count == 0 or key_size == 0:
    return '/* noop xor */'

start = common.label('start')

## Set up the register context
regctx = {'x1': address, 'x2': key}
%>
    /* xor(${pretty(key)}, ${pretty(address)}, ${pretty(count)}) */
    ${aarch64.setregs(regctx)}
    add x0, x1, #${count}
${start}:
    ldr x3, [x1]
    eor x3, x3, x2
    str x3, [x1]
    add x1, x1, ${key_size}
    cmp x1, x0
    blt  ${start}
