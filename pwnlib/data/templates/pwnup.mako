<%page args="binary, host=None, port=None, user=None, password=None, remote_path=None, quiet=False"/>\
<%
import os
import sys

from pwnlib.context import context as ctx
from pwnlib.elf.elf import ELF
from pwnlib.util.sh_string import sh_string
from elftools.common.exceptions import ELFError

argv = list(sys.argv)
argv[0] = os.path.basename(argv[0])

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
#!/usr/bin/env python
# -*- coding: utf-8 -*-
%if not quiet:
# This exploit template was generated via:
# $ ${' '.join(map(sh_string, argv))}
%endif
from pwn import *

%if not quiet:
# Set up pwntools for the correct architecture
%endif
%if ctx.binary:
exe = context.binary = ELF(${binary_repr})
<% binary_repr = 'exe.path' %>
%else:
context.update(arch='i386')
exe = ${binary_repr}
<% binary_repr = 'exe' %>
%endif

%if not quiet:
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
%if host or port or user:
# ./exploit.py GDB HOST=example.com PORT=4141
%endif
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

%if ssh:
# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)
%endif

%if host:
def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([${binary_repr}] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([${binary_repr}] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
  %if ssh:
    '''Execute the target binary on the remote host'''
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw)
  %else:
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io
  %endif
%endif

%if host:
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)
%else:
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([${binary_repr}] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([${binary_repr}] + argv, *a, **kw)
%endif

%if exe or remote_path:
%if not quiet:
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
%endif
gdbscript = '''
%if ctx.binary:
  %if 'main' in ctx.binary.symbols:
tbreak main
  %elif 'DYN' != ctx.binary.elftype:
tbreak *0x{exe.entry:x}
  %endif
%endif
continue
'''.format(**locals())
%endif


%if not quiet:
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
%else:
# -- Exploit goes here --
%endif
%if ctx.binary and not quiet:
# ${'%-10s%s-%s-%s' % ('Arch:',
                       ctx.binary.arch,
                       ctx.binary.bits,
                       ctx.binary.endian)}
%for line in ctx.binary.checksec(color=False).splitlines():
# ${line}
%endfor
%endif

io = start()

%if not quiet:
# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
%endif

io.interactive()
