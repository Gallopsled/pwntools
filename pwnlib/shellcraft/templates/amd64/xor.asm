<%
  from pwnlib.shellcraft import pretty, common, amd64, registers
  from pwnlib.util.packing import pack, unpack
  from pwnlib.context import context as ctx
  from pwnlib.log import getLogger
%>
<%page args="key, address, count"/>
<%docstring>
XORs data a constant value.

Args:
    key (int,str): XOR key either as a 8-byte integer,
                   If a string, length must be a power of two,
                   and not longer than 8 bytes.
                   Alternately, may be a register.
    address (int): Address of the data (e.g. 0xdead0000, 'esp')
    count (int): Number of bytes to XOR, or a register containing
                 the number of bytes to XOR.

Example:

    >>> sc  = shellcraft.read(0, 'rsp', 32)
    >>> sc += shellcraft.xor(0xdeadbeef, 'rsp', 32)
    >>> sc += shellcraft.write(1, 'rsp', 32)
    >>> io = run_assembly(sc)
    >>> io.send(cyclic(32))
    >>> result = io.recvn(32)
    >>> expected = xor(cyclic(32), p32(0xdeadbeef))
    >>> result == expected
    True

</%docstring>
<%
log = getLogger('pwnlib.shellcraft.templates.amd64.xor')

# By default, assume the key is a register
key_size   = ctx.bytes
key_pretty = key

key_register = registers.get_register(key)

if key_register:
    assert key_register.bytes == ctx.bytes
else:
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

## Determine the move size
word_name = {1:'BYTE', 2:'WORD', 4:'DWORD', 8:'QWORD'}[key_size]

## Set up the register context
regctx = {'rax': count, 'rcx': address}
if key_register and key_register.name in regctx:
    regctx['rbx'] = key
    key_pretty = 'rbx'
%>
    /* xor(${pretty(key)}, ${pretty(address)}, ${pretty(count)}) */
    ${amd64.setregs(regctx)}
    add rax, rcx
${start}:
    xor ${word_name} PTR [rcx], ${key_pretty}
    add rcx, ${key_size}
    cmp rcx, rax
    jb  ${start}
