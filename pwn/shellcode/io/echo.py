from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def echo(str, out = 'STD_OUT'):
    """Args: str, [out]
    Writes <str> to <out> (default: STD_OUT).  Reads from STD_IN if <str> is 'STDIN'."""
    if str == 'STDIN':
        str = sys.stdin.read()
    str = repr(str)[1:-1]
    return """
        %%define str `%(str)s`
        xor eax, eax

        %%strlen cnt str
        %%if cnt < 256
          cdq                   ; EDX := 0
          mov dl, cnt
        %%else
        %%if cnt < 65536
          cdq                   ; EDX := 0
          mov dx, cnt
        %%else
          mov edx, cnt
        %%endif
        %%endif

        pushstr str
        setfd ebx, %(out)s
        mov ecx, esp
        mov al, SYS_write
        int 0x80
""" % {'str' : str,
       'out' : out
       }
