<%page args="binary, host=None, port=None, user=None, password=None, remote_path=None"/>\
<%
from pwnlib.context import context as ctx
from pwnlib.elf.elf import ELF
from elftools.common.exceptions import ELFError

import os
try:
    if binary:
        ctx.binary = ELF(binary, checksec=False)
except ELFError:
    pass

if not binary:
    binary = './path/to/binary'

exe = os.path.basename(binary)

ssh = user or password
if ssh and not port:
    port = 22
elif host and not port:
    port = 4141

remote_path = remote_path or exe
password = password or 'secret1234'
binary_repr = repr(binary)
%>\
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
%if ctx.binary:
exe = context.binary = ELF(${binary_repr})
<% binary_repr = 'exe.path' %>
%else:
context.update(arch='i386')
exe = ${binary_repr}
<% binary_repr = 'exe' %>
%endif

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
%if host or port or user:
# ./exploit.py GDB HOST=example.com PORT=4141
%endif
%if host:
host = args.HOST or ${repr(host)}
%endif
%if port:
port = int(args.PORT or ${port})
%endif
%if user:
user = args.USER or ${repr(user)}
password = args.PASSWORD or ${repr(password)}
%endif
%if ssh:
remote_path = ${repr(remote_path)}
%endif

%if exe or remote_path:
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
%if ctx.binary:
  %if 'main' in ctx.binary.symbols:
break *0x{exe.symbols.main:x}
  %else:
break *0x{exe.entry:x}
  %endif
%endif
continue
'''.format(**locals())
%endif

%if ssh:
# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)
%endif

%if host:
# Execute the target binary locally
def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

%if ssh:
# Execute the target binary on the remote host
%else:
# Connect to the process on the remote host
%endif
def remote(argv=[], *a, **kw):
  %if ssh:
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw)
  %else:
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io
  %endif
%endif

%if host:
start = local if args.LOCAL else remote
%else:
def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([${binary_repr}] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([${binary_repr}] + argv, *a, **kw)
%endif

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
