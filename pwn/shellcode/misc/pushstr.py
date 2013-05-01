from pwn.internal.shellcode_helper import *

def _hex(n):
    return hex(n).replace('L', '')

@shellcode_reqs(arch=['i386', 'amd64'])
def pushstr(string, null = True, arch = None):
    '''Args: string [null = True]

    Pushes a string to the stack. If null is True, then it also
    null-terminates the string.

    On amd64 clobbers rax for most strings longer than 4 bytes.
'''

    if null:
        string += '\x00'

    if not string:
        return ''

    def fix(out):
        return '\n'.join('    ' + s for s in out)

    if arch == 'i386':
        return fix(_pushstr_i386(string))
    elif arch == 'amd64':
        return fix(_pushstr_amd64(string))
    bug("OS/arch combination (%s, %s) not supported for pushstr" % (os, arch))

def _pushstr_i386(string):
    out = []

    if ord(string[-1]) >= 128:
        extend = '\xff'
    else:
        extend = '\x00'

    string = string.ljust(align(4, len(string)), extend)

    for s in group(4, string)[::-1]:
        n = u32(s)
        sign = n - (2 * (n & 2**31))

        if n == 0:
            out.append('push 1 ; %s' % (repr(s)))
            out.append('dec byte [esp]')
        elif -128 <= sign < 128 or ('\x00' not in s and '\n' not in s):
            out.append('push %s ; %s' % (_hex(n), repr(s)))
        else:
            a,b = xor_pair(s, avoid = '\x00\n')
            out.append('push %s' % _hex(u32(a)))
            out.append('xor dword [esp], %s ; %s' % (_hex(u32(b)), repr(s)))
    return out

def _pushstr_amd64(string):
    out = []

    if ord(string[-1]) >= 128:
        extend = '\xff'
    else:
        extend = '\x00'

    string = string.ljust(align(8, len(string)), extend)

    for s in group(8, string)[::-1]:
        n = u64(s)
        sign = n - (2 * (n & 2**63))

        if n == 0:
            out.append('push 1 ; %s' % (repr(s)))
            out.append('dec byte [rsp]')
        elif -128 <= sign < 128:
            out.append('push %s ; %s' % (_hex(n), repr(s)))
        else:
            if s[4:] == 4*('\xff' if sign<0 else '\x00'):
                if '\n' not in s[:4] and '\x00' not in s[:4]:
                    out.append('push %s ; %s' % (_hex(n), repr(s)))
                else:
                    a,b = xor_pair(s[:4], avoid = '\x00\n')
                    a = u32(a)
                    b = u32(b)
                    a, b = max(a,b), min(a,b)
                    out.append('push %s' % _hex(a))
                    out.append('xor dword [rsp], %s ; %s' % (_hex(b), repr(s)))
            else:
                if '\n' not in s and ('\x00' not in s and '\n' not in s):
                    out.append('mov rax, %s ; %s' % (_hex(n), repr(s)))
                    out.append('push rax')
                else:
                    a,b = xor_pair(s, avoid = '\x00')
                    out.append('mov rax, %s' % _hex(u64(a)))
                    out.append('push rax')
                    out.append('mov rax, %s ; %s' % (_hex(u64(b)), repr(s)))
                    out.append('xor qword [rsp], rax')
    return out
