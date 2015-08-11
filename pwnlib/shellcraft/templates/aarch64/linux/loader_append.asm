<%
    from pwnlib.shellcraft.aarch64.linux import loader
    from pwnlib.shellcraft import common
%>
<%docstring>
Loads a statically-linked ELF into memory and transfers control.

Similar to loader.asm but loads an appended ELF.

Arguments:
    data(str): If a valid filename, the data is loaded from the named file.
               Otherwise, this is treated as raw ELF data to append.
               If ``None``, it is ignored.

Example:

The following doctest is commented out because it doesn't work on Travis
for reasons I cannot diagnose.  However, it should work just fine :-)

    # >>> gcc = process(['aarch64-linux-gnu-gcc','-xc','-static','-Wl,-Ttext-segment=0x20000000','-'])
    # >>> gcc.write('''
    # ... int main() {
    # ...     printf("Hello, %s!\\n", "world");
    # ... }
    # ... ''')
    # >>> gcc.shutdown('send')
    # >>> gcc.poll(True)
    # 0
    # >>> sc = shellcraft.loader_append('a.out')
    # >>> run_assembly(sc).recvline()
    # 'Hello, world!\n'

</%docstring>
<%page args="data = None"/>
<%
there = common.label('there')
here  = common.label('here')
%>
    b ${there}
${here}:
    mov x0, x30 /* lr */
    ${loader('x0')}
${there}:
    bl ${here}
%if data:
<%
import os

if os.path.isfile(data):
    with open(data, 'rb') as f:
        data = f.read()
%>
    ${'.string "%s"' % ''.join('\\x%02x' % c for c in bytearray(data))}
%endif
