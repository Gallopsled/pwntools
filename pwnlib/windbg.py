# -*- coding: utf-8 -*-
"""
During exploit development, it is frequently useful to debug the
target binary under WinDbg.

Pwntools makes this easy-to-do with a handful of helper routines, designed
to make your exploit-debug-update cycles much faster.

Useful Functions
----------------

- :func:`attach` - Attach to an existing process
- :func:`debug` - Start a new process under a debugger, stopped at the first instruction
- :func:`debug_shellcode` - Build a binary with the provided shellcode, and start it under a debugger

Debugging Tips
--------------

The :func:`attach` and :func:`debug` functions will likely be your bread and
butter for debugging.

Both allow you to provide a script to pass to GDB when it is started, so that
it can automatically set your breakpoints.

Attaching to Processes
~~~~~~~~~~~~~~~~~~~~~~

To attach to an existing process, just use :func:`attach`.  It is surprisingly
versatile, and can attach to a :class:`.process` for simple
binaries, or will automatically find the correct process to attach to for a
forking server, if given a :class:`.remote` object.

Spawning New Processes
~~~~~~~~~~~~~~~~~~~~~~

Attaching to processes with :func:`attach` is useful, but the state the process
is in may vary.  If you need to attach to a process very early, and debug it from
the very first instruction (or even the start of ``main``), you instead should use
:func:`debug`.

When you use :func:`debug`, the return value is a :class:`.tube` object
that you interact with exactly like normal.

Tips and Troubleshooting
------------------------

``NOPTRACE`` magic argument
~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's quite cumbersom to comment and un-comment lines containing `attach`.

You can cause these lines to be a no-op by running your script with the
``NOPTRACE`` argument appended, or with ``PWNLIB_NOPTRACE=1`` in the environment.

::

    $ python exploit.py NOPTRACE
    [+] Starting local process '/bin/bash': Done
    [!] Skipping debug attach since context.noptrace==True
    ...

Member Documentation
===============================
"""
from __future__ import absolute_import

import os
import random
import re
import shlex
import tempfile
import time
import subprocess

from pwnlib import atexit
from pwnlib import tubes
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import misc
from pwnlib.util import proc

log = getLogger(__name__)

# def _gdbserver_args(pid=None, path=None, args=None, which=None):
    # """_gdbserver_args(pid=None, path=None) -> list

    # Sets up a listening gdbserver, to either connect to the specified
    # PID, or launch the specified binary by its full path.

    # Arguments:
        # pid(int): Process ID to attach to
        # path(str): Process to launch
        # args(list): List of arguments to provide on the debugger command line
        # which(callaable): Function to find the path of a binary.

    # Returns:
        # A list of arguments to invoke gdbserver.
    # """
    # if [pid, path, args].count(None) != 2:
        # log.error("Must specify exactly one of pid, path, or args")

    # if not which:
        # log.error("Must specify which.")

    # gdbserver = ''

    # if not args:
        # args = [str(path or pid)]

    # # Android targets have a distinct gdbserver
    # if context.bits == 64:
        # gdbserver = which('gdbserver64')

    # if not gdbserver:
        # gdbserver = which('gdbserver')

    # if not gdbserver:
        # log.error("gdbserver is not installed")

    # orig_args = args

    # gdbserver_args = [gdbserver]
    # if context.aslr:
        # gdbserver_args += ['--no-disable-randomization']
    # else:
        # log.warn_once("Debugging process with ASLR disabled")

    # if pid:
        # gdbserver_args += ['--once', '--attach']

    # gdbserver_args += ['localhost:0']
    # gdbserver_args += args

    # return gdbserver_args

# def _gdbserver_port(gdbserver, ssh):
    # which = _get_which(ssh)

    # # Process /bin/bash created; pid = 14366
    # # Listening on port 34816
    # process_created = gdbserver.recvline()
    # gdbserver.pid   = int(process_created.split()[-1], 0)

    # listening_on = ''
    # while 'Listening' not in listening_on:
        # listening_on    = gdbserver.recvline()

    # port = int(listening_on.split()[-1])

    # # Set up port forarding for SSH
    # if ssh:
        # remote   = ssh.connect_remote('127.0.0.1', port)
        # listener = tubes.listen.listen(0)
        # port     = listener.lport

        # # Disable showing GDB traffic when debugging verbosity is increased
        # remote.level = 'error'
        # listener.level = 'error'

        # # Hook them up
        # remote <> listener

    # # Set up port forwarding for ADB
    # elif context.os == 'android':
        # adb.forward(port)

    # return port

# def _get_which(ssh=None):
    # if ssh:                        return ssh.which
    # elif context.os == 'android':  return adb.which
    # else:                          return misc.which

# def _get_runner(ssh=None):
    # if ssh:                        return ssh.process
    # elif context.os == 'android':  return adb.process
    # else:                          return tubes.process.process

# @LocalContext
# def debug(args, gdbscript=None, exe=None, env=None, **kwargs):
    # """debug(args) -> tube

    # Launch a GDB server with the specified command line,
    # and launches GDB to attach to it.

    # Arguments:
        # args(list): Arguments to the process, similar to :class:`.process`.
        # gdbscript(str): GDB script to run.
        # exe(str): Path to the executable on disk
        # env(dict): Environment to start the binary in

    # Returns:
        # :class:`.process` or :class:`.ssh_channel`: A tube connected to the target process

    # Notes:

        # The debugger is attached automatically, and you can debug everything
        # from the very beginning.  This requires that both ``gdb`` and ``gdbserver``
        # are installed on your machine.

        # .. code-block:: python

            # # Create a new process, and stop it at 'main'
            # io = gdb.debug('bash', '''
            # break main
            # continue
            # ''')

        # When GDB opens via :func:`debug`, it will initially be stopped on the very first
        # instruction of the dynamic linker (``ld.so``) for dynamically-linked binaries.

        # Only the target binary and the linker will be loaded in memory, so you cannot
        # set breakpoints on shared library routines like ``malloc`` since ``libc.so``
        # has not even been loaded yet.

        # There are several ways to handle this:

        # 1. Set a breakpoint on the executable's entry point (generally, ``_start``)
            # - This is only invoked after all of the required shared libraries
              # are loaded.
            # - You can generally get the address via the GDB command ``info file``.
        # 2. Use pending breakpoints via ``set breakpoint pending on``
            # - This has the side-effect of setting breakpoints for **every** function
              # which matches the name.  For ``malloc``, this will generally set a
              # breakpoint in the executable's PLT, in the linker's internal ``malloc``,
              # and eventaully in ``libc``'s malloc.
        # 3. Wait for libraries to be loaded with ``set stop-on-solib-event 1``
            # - There is no way to stop on any specific library being loaded, and sometimes
              # multiple libraries are loaded and only a single breakpoint is issued.
            # - Generally, you just add a few ``continue`` commands until things are set up
              # the way you want it to be.

        # .. code-block:: python

            # # Create a new process, and stop it at 'main'
            # io = gdb.debug('bash', '''
            # # Wait until we hit the main executable's entry point
            # break _start
            # continue

            # # Now set breakpoint on shared library routines
            # break malloc
            # break free
            # continue
            # ''')
       
    # """
    # if isinstance(args, (int, tubes.process.process )):
        # log.error("Use gdb.attach() to debug a running process")

    # if env is None:
        # env = os.environ

    # if isinstance(args, (str, unicode)):
        # args = [args]

    # orig_args = args

    # runner = _get_runner(ssh)
    # which  = _get_which(ssh)

    # if context.noptrace:
        # log.warn_once("Skipping debugger since context.noptrace==True")
        # return runner(args, executable=exe, env=env)

    # if ssh or context.native or (context.os == 'android'):
        # args = _gdbserver_args(args=args, which=which)
    # else:
        # qemu_port = random.randint(1024, 65535)
        # args = [get_qemu_user(), '-g', str(qemu_port)] + args

    # # Make sure gdbserver/qemu is installed
    # if not which(args[0]):
        # log.error("%s is not installed" % args[0])

    # exe = exe or which(orig_args[0])
    # if not exe:
        # log.error("%s does not exist" % orig_args[0])

    # # Start gdbserver/qemu
    # # (Note: We override ASLR here for the gdbserver process itself.)
    # gdbserver = runner(args, env=env, aslr=1, **kwargs)

    # # Set the .executable on the process object.
    # gdbserver.executable = which(orig_args[0])

    # # Find what port we need to connect to
    # if context.native or (context.os == 'android'):
        # port = _gdbserver_port(gdbserver, ssh)
    # else:
        # port = qemu_port

    # host = '127.0.0.1'
    # if not ssh and context.os == 'android':
        # host = context.adb_host

    # attach((host, port), exe=exe, gdbscript=gdbscript, need_ptrace_scope = False, ssh=ssh)

    # # gdbserver outputs a message when a client connects
    # garbage = gdbserver.recvline(timeout=1)

    # if "Remote debugging from host" not in garbage:
        # gdbserver.unrecv(garbage)

    # return gdbserver

# def get_gdb_arch():
    # return {
        # 'amd64': 'i386:x86-64',
        # 'powerpc': 'powerpc:common',
        # 'powerpc64': 'powerpc:common64',
        # 'mips64': 'mips:isa64',
        # 'thumb': 'arm'
    # }.get(context.arch, context.arch)

def binary():
    """binary() -> str

    Returns:
        str: Path to the appropriate ``windbg`` binary to use.
    """
    windbg = misc.which('windbg.exe')
    if not windbg:
        log.error('windbg is not installed or in system PATH\n')

    return windbg

@LocalContext
def attach(target, windbgscript = None, windbg_args = [] ):
    """attach(target, windbgscript = None, exe = None, windbg_args = None ) -> None

    Start WinDbg in a new process and attach to `target`.

    Arguments:
        target: The target to attach to.
        windbgscript(:obj:`str` or :obj:`file`): WinDbg script to run after attaching.
        windbg_args(list): List of additional arguments to pass to WinDbg.

    Returns:
        PID of the WinDbg process.

    Notes:

        The ``target`` argument is very robust, and can be any of the following:

        :obj:`int`
            PID of a process
        :obj:`str`
            Process name.  The youngest process is selected.
        :class:`.process`
            Process to connect to        
       
        .. code-block:: python

            # Attach directly to pid 1234
            windbg.attach(1234)

        .. code-block:: python

            # Attach to the youngest "bash" process
            windbg.attach('bash')

        .. code-block:: python

            # Start a process
            bash = process('bash')

            # Attach the debugger
            windbg.attach(bash, '''
            set follow-fork-mode child
            break execve
            continue
            ''')

            # Interact with the process
            bash.sendline('whoami')
       
    """
    if context.noptrace:
        log.warn_once("Skipping debug attach since context.noptrace==True")
        return

    # if windbgscript is a file object, then read it;
    if isinstance(windbgscript, file):
        with windbgscript:
            windbgscript = windbgscript.read()

    # enable gdb.attach(p, 'continue')
    if windbgscript and not windbgscript.endswith('\n'):
        windbgscript += '\n'

    # gdb script to run before `gdbscript`
    # pre = ''
    # if not context.native:
        # pre += 'set endian %s\n' % context.endian
        # pre += 'set architecture %s\n' % get_gdb_arch()

    # let's see if we can find a pid to attach to
    pid = None
    if isinstance(target, (int, long)):
        # target is a pid, easy peasy
        pid = target
    elif isinstance(target, str):
        # pidof picks the youngest process
        pidof = proc.pidof

        pids = pidof(target)
        if not pids:
            log.error('No such process: %s' % target)
        pid = pids[0]
        log.info('Attaching to youngest process "%s" (PID = %d)' %
                 (target, pid))
   
    elif isinstance(target, tubes.process.process):
        pid = proc.pidof(target)[0]
    #elif isinstance(target, win.dumpfile.Dumpfile):
    #    pre += ' -z %s\n' % target.path
    else:
        log.error("don't know how to attach to target: %r" % target)

    if not pid:
        log.error('could not find target process')

    cmd = [binary()]
    for arg in windbg_args:
        cmd.append(arg)
     
    if pid:
        cmd.append("-p")
        cmd.append('%d' % pid)

    #windbgscript = pre + (windbgscript or '')
    if windbgscript:
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.windbg',
                                          delete = False)
        log.debug('Wrote windbgscript script to %r\n%s' % (tmp.name, windbgscript))
        #windbgscript = '.shell del %s\n%s' % (tmp.name, windbgscript)

        tmp.write(windbgscript)
        tmp.close()
        cmd.append('-c')
        cmd.append('$><%s' % (tmp.name))
    
    log.info("Launching a new process: %r" % cmd)
    p = subprocess.Popen( cmd, executable=cmd[0] )
    windbg_pid = p.pid

    if pid and context.native:
        proc.wait_for_debugger(pid)

    return windbg_pid

# def find_module_addresses(binary, ssh=None, ulimit=False):
    # """
    # Cheat to find modules by using GDB.

    # We can't use ``/proc/$pid/map`` since some servers forbid it.
    # This breaks ``info proc`` in GDB, but ``info sharedlibrary`` still works.
    # Additionally, ``info sharedlibrary`` works on FreeBSD, which may not have
    # procfs enabled or accessible.

    # The output looks like this:

    # ::

        # info proc mapping
        # process 13961
        # warning: unable to open /proc file '/proc/13961/maps'

        # info sharedlibrary
        # From        To          Syms Read   Shared Object Library
        # 0xf7fdc820  0xf7ff505f  Yes (*)     /lib/ld-linux.so.2
        # 0xf7fbb650  0xf7fc79f8  Yes         /lib32/libpthread.so.0
        # 0xf7e26f10  0xf7f5b51c  Yes (*)     /lib32/libc.so.6
        # (*): Shared library is missing debugging information.

    # Note that the raw addresses provided by ``info sharedlibrary`` are actually
    # the address of the ``.text`` segment, not the image base address.

    # This routine automates the entire process of:

    # 1. Downloading the binaries from the remote server
    # 2. Scraping GDB for the information
    # 3. Loading each library into an ELF
    # 4. Fixing up the base address vs. the ``.text`` segment address

    # Arguments:
        # binary(str): Path to the binary on the remote server
        # ssh(pwnlib.tubes.tube): SSH connection through which to load the libraries.
            # If left as :const:`None`, will use a :class:`pwnlib.tubes.process.process`.
        # ulimit(bool): Set to :const:`True` to run "ulimit -s unlimited" before GDB.

    # Returns:
        # A list of pwnlib.elf.ELF objects, with correct base addresses.

    # Example:

    # >>> with context.local(log_level=9999): # doctest: +SKIP
    # ...     shell = ssh(host='bandit.labs.overthewire.org',user='bandit0',password='bandit0')
    # ...     bash_libs = gdb.find_module_addresses('/bin/bash', shell)
    # >>> os.path.basename(bash_libs[0].path) # doctest: +SKIP
    # 'libc.so.6'
    # >>> hex(bash_libs[0].symbols['system']) # doctest: +SKIP
    # '0x7ffff7634660'
    # """
    # #
    # # Download all of the remote libraries
    # #
    # if ssh:
        # runner     = ssh.run
        # local_bin  = ssh.download_file(binary)
        # local_elf  = elf.ELF(os.path.basename(binary))
        # local_libs = ssh.libs(binary)

    # else:
        # runner     = tubes.process.process
        # local_elf  = elf.ELF(binary)
        # local_libs = local_elf.libs

    # entry      = local_elf.header.e_entry

    # #
    # # Get the addresses from GDB
    # #
    # libs = {}
    # cmd  = "gdb -q --args %s" % (binary)
    # expr = re.compile(r'(0x\S+)[^/]+(.*)')

    # if ulimit:
        # cmd = 'sh -c "(ulimit -s unlimited; %s)"' % cmd

    # cmd = shlex.split(cmd)

    # with runner(cmd) as gdb:
        # if context.aslr:
            # gdb.sendline('set disable-randomization off')
        # gdb.send("""
        # set prompt
        # break *%#x
        # run
        # """ % entry)
        # gdb.clean(2)
        # gdb.sendline('info sharedlibrary')
        # lines = gdb.recvrepeat(2)

        # for line in lines.splitlines():
            # m = expr.match(line)
            # if m:
                # libs[m.group(2)] = int(m.group(1),16)
        # gdb.sendline('kill')
        # gdb.sendline('y')
        # gdb.sendline('quit')

    # #
    # # Fix up all of the addresses against the .text address
    # #
    # rv = []

    # for remote_path,text_address in sorted(libs.items()):
        # # Match up the local copy to the remote path
        # try:
            # path     = next(p for p in local_libs.keys() if remote_path in p)
        # except StopIteration:
            # print "Skipping %r" % remote_path
            # continue

        # # Load it
        # lib      = elf.ELF(path)

        # # Find its text segment
        # text     = lib.get_section_by_name('.text')

        # # Fix the address
        # lib.address = text_address - text.header.sh_addr
        # rv.append(lib)

    # return rv

# def corefile(process):
    # r"""Drops a core file for the process.

    # Arguments:
        # process: Process to dump

    # Returns:
        # :class:`.Core`: The generated core file
    # """

    # if context.noptrace:
        # log.warn_once("Skipping corefile since context.noptrace==True")
        # return

    # corefile_path = './core.%s.%i' % (os.path.basename(process.executable),
                                    # process.pid)

    # # Due to https://sourceware.org/bugzilla/show_bug.cgi?id=16092
    # # will disregard coredump_filter, and will not dump private mappings.
    # if version() < (7,11):
        # log.warn_once('The installed GDB (%s) does not emit core-dumps which '
                      # 'contain all of the data in the process.\n'
                      # 'Upgrade to GDB >= 7.11 for better core-dumps.' % binary())

    # # This is effectively the same as what the 'gcore' binary does
    # gdb_args = ['-batch',
                # '-q',
                # '--nx',
                # '-ex', '"set pagination off"',
                # '-ex', '"set height 0"',
                # '-ex', '"set width 0"',
                # '-ex', '"set use-coredump-filter on"',
                # '-ex', '"generate-core-file %s"' % corefile_path,
                # '-ex', 'detach']

    # with context.local(terminal = ['sh', '-c']):
        # with context.quiet:
            # pid = attach(process, gdb_args=gdb_args)
            # os.waitpid(pid, 0)

    # return elf.corefile.Core(corefile_path)

