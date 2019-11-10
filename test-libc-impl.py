#!/usr/bin/env python3

from pwn import *

context.log_level = 'debug'

e = ELF('/lib/x86_64-linux-gnu/libc.so.6', libc_impl_find=True)

print(e.functions['__memcmp_sse2'])