<%docstring>
Invokes the cache-flush operation, without using any NULL or newline bytes.

Effectively is just:

    mov   r0, #0
    mov   r1, #-1
    mov   r2, #0
    swi   0x9F0002

How this works:

    ... However, SWI generates a software interrupt and to the
    interrupt handler, 0x9F0002 is actually data and as a result will
    not be read via the instruction cache, so if we modify the argument
    to SWI in our self-modifyign code, the argument will be read
    correctly.
</%docstring>
    adr  r6, cacheflush
    movw r5, 0xffff
    add  r5, r5, 3
    strh r5, [r6]
    eor r7, r7, r7
    push {r7, lr}
    sub r7, r7, #1
    push {r7}
    add r7, r7, #1
    push {r7}
    pop {r0, r1, r2, lr}
cacheflush:
    swimi 0x9f4141
