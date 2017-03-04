.. testsetup:: *

	from pwn import *
	import tempfile

:mod:`pwnlib.fmtstr` --- Format string bug exploitation tools
=============================================================

Utilities and helpers for format string exploitation.

Terminology
------------

Basic format string exploitation relies on a stack layout that looks
something like the following:

::

    +-----------------------------------------
    | return address
    |
    |   This is the address that printf() or
    |   similar will return to when it
    |   completes.
    +-----------------------------------------
    | (optional) sprintf buffer
    |
    |   If our format string use used with
    |   e.g. sprintf, a pointer to the target
    |   buffer lives here.
    +-----------------------------------------
    | (optional) snprintf buffer size
    |
    |   If our format string use used with
    |   e.g. snprintf, the size of the buffer
    |   is stored here.
    +-----------------------------------------
    | format specifier string **POINTER**
    |
    |   This is a *pointer* to a format
    |   string somewhere else in memory.
    |
    |   Generally, and ideally, this resides
    |   on the stack (e.g. in argv[1])
    +-----------------------------------------
    | format arguments
    |
    |   Under normal usage, these are the
    |   arguments which are printed with e.g.
    |   "%d" and "%s".
    |
    |   However, printf() and friends are all
    |   variable-argument routines, so the
    |   "number of arguments" is not defined.
    |
    |   By using more format specifiers than
    |   format arguments provided, we can use
    |   whatever is on the stack.
    +-----------------------------------------
    | msic stack contents
    |
    |   These are local variables used by the
    |   function which calls printf().
    |
    |   Some of these values we may be able
    |   to influence, or wish to modify.
    |
    |\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
    | controlled stack buffer
    | (generally the format string)
    |
    |   Our format specifier string usually
    |   lives on the stack, either in argv[] or
    |   in some other stack-based buffer.
    |
    |   If the format string is in the heap,
    |   generally there will be some other buffer
    |   on the stack that we control (e.g. argv[]).
    +-----------------------------------------

In order to perform a format string exploit, it is necessary
to have control of a buffer on the stack.  We can encode a raw
pointer into this buffer, and use the ``%n`` format specifier
to write "the number of characters written" to this address.

Generally, the value that we wish to write is very large (e.g.
0xdeadbeef).  While we can use the ``%c`` format specifier to
emit an arbitrary number of characters, and eventually emit
a large quantity, this is generally undesireable as it takes
a lot of bandwidth.

Instead, we can leverage ``%hn`` and ``%hhn`` format specifiers
to perform one- or two-byte writes at a time.  This requires
encoding multiple pointers on the stack, and performing multiple
writes.

The distance between "return address" (above) and the "controlled
stack buffer", is considered the "argument index" which we will
use with the ``%n`` family of format specifiers.  This index is not
measured in bytes, but in pointer-widths.

If we know that the return address and our controlled buffer are
0x400 bytes apart, this implies that the 256th argument index
(in 32-bit programs) would point to our controlled buffer.

By putting a the address we want to overwrite in the buffer
(let's assume ``0xcafebabe``), we can write arbitrary values to
that address.

::

    format_string = "%256$n"
    controlled_stack_buffer = "\xbe\xba\xfe\ca"

In the above scenario, we will write the value "0" to address ``0xcafebabe``.

Tips and Tricks
---------------

Frequently, it is easier to modify a GOT pointer than to overwrite
a stack variable.

Example
^^^^^^^^^^^^^^^

Let's assume a small binary with a simple format string vulnerability.

::

    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>

    void vulnerable() {
        char buffer[64];
        memset(buffer, 0, sizeof buffer);
        read(0, buffer, 64);
        printf(buffer);
    }

    int main() {
        vulnerable();
        return 0;
    }

::

    $ clang test.c -fomit-frame-pointer -m32 -fno-stack-protector

The compiled function and its stack layout looks something like the
disassembly shown below.

::

     public vulnerable
     vulnerable proc near                    ; CODE XREF: main+3p

     arg0= dword ptr -5Ch
     arg1= dword ptr -58h
     arg2= dword ptr -54h
     var_50= dword ptr -50h
     var_4C= dword ptr -4Ch
     stack_buffer= byte ptr -48h
     var_8= dword ptr -8
     var_4= dword ptr -4

         push    edi
         push    esi
         sub     esp, 54h
         mov     [esp+5Ch+arg0], 40h         ; size
         call    _malloc

         mov     esi, eax
         lea     edi, [esp+5Ch+stack_buffer]
         mov     [esp+5Ch+arg1], edi         ; buf
         mov     [esp+5Ch+arg2], 40h         ; nbytes
         mov     [esp+5Ch+arg0], 0           ; fd
         call    _read

         mov     [esp+5Ch+stack_buffer+3Fh], 0
         mov     [esp+5Ch+arg2], edi
         mov     [esp+5Ch+arg1], edi
         mov     [esp+5Ch+arg0], offset format ; "Stack [%p]: %s\n"
         call    _printf

         mov     [esp+5Ch+arg1], esi         ; buf
         mov     [esp+5Ch+arg2], 40h         ; nbytes
         mov     [esp+5Ch+arg0], 0           ; fd
         call    _read

         mov     [esp+5Ch+stack_buffer+3Fh], 0
         mov     [esp+5Ch+arg2], esi
         mov     [esp+5Ch+arg1], esi
         mov     [esp+5Ch+arg0], offset aFormatPS ; "Format [%p]: %s\n"
         call    _printf

         mov     [esp+5Ch+arg0], esi         ; format
         call    _printf

         call    _getuid

         add     esp, 54h
         pop     esi
         pop     edi
         retn

     vulnerable endp

When printf() is invoked, arg0 is at the top of the stack.

The *printf family of functions uses index 1 to refer to the
first (zeroth) argument.

Thus, arg0 is at argument index ``1$``.
We can print out its address with the following format string ``%1$p``.

If we wished to print out the first four bytes of our stack-based buffer,
we can calculate that it is at index ``((0x5C - 0x48) / 4) + 1``.  The
``+ 1`` is because ``*printf`` uses 1-based indexing.  ``0x5c`` is the
top of the stack as seen here, and ``0x44`` is the offset of our buffer.
Given this, we would use ``%6$x`` to print out the first four bytes as
a hexadecimal value.

### Note Regarding 64-Bit Linux

On amd64 Linux, the first six arguments are stored in registers.

Normally, these would be available in ``1$`` through ``6$`` via
the ``*printf`` family.

However, the first argument (``rdi``) is not available via indexing
in this manner for ``printf``, nor are e.g. the first three arguments
available for ``snprintf`` (``rdi``, ``rsi``, ``rdx``).  This is just
an implementation detail.

This means that the "first" item on the stack is at index ``6$``
for ``printf``, and ``4$`` for ``snprintf``.

However, the first six arguments are still available

.. automodule:: pwnlib.fmtstr
   :members:
