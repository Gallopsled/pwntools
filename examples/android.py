from __future__ import print_function

import gdb
from pwn import adb, context

# Tell pwntools that the target is an Android device
context.os = "android"
context.arch = "aarch64"  # or 'arm'

# Optionally, set the remote ADB server address
context.adb_host = "172.16.110.1"

# Wait for a device to become available
print(adb.wait_for_device())

# Who am I?
print(adb.process("id").recvall().strip())

# Interactive sessions!
io = adb.shell()
io.sendline("echo Hello, world; exit")
print(io.recvall().replace("\r\n", "\n").strip())

# Debugging!
gdb.debug("sh").interactive()
