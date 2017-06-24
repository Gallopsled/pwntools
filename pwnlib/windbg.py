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
import tempfile
import subprocess

from pwnlib import atexit
from pwnlib import tubes
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import misc
from pwnlib.util import proc

log = getLogger(__name__)

# @LocalContext
def debug(args, windbgscript=None, exe=None, env=None ):
    """debug(args) -> tube

    Launch a process in a suspended state, attach debugger and return process

    Arguments:
        args(list): Arguments to the process, similar to :class:`.process`.
        windbgscript(str): WinDbg script to run.
        exe(str): Path to the executable on disk

    Returns:
        :class:`.process`: A tube connected to the target process

    Notes:

        .. code-block:: python

            # Create a new process, and stop it at 'main'
            io = windbg.debug('calc', '''
            bp $exentry
            go
            ''')

        When WinDbg opens via :func:`debug`, it will initially be stopped on the very first
        instruction of the entry point.
                  
       
    """
    if isinstance(args, (int, tubes.process.process )):
        log.error("Use windbg.attach() to debug a running process")

    orig_args = args
    
    if context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return tubes.process.process(args, executable=exe, env=env )

    exe = exe or misc.which(orig_args[0])
    if not exe:
        log.error("%s does not exist" % orig_args[0])

    final_script = ['~0m']
    if windbgscript:
        final_script += windbgscript
    
    #Start the process in a suspended start
    p = tubes.process.process(args, executable=exe, env=env, creationflags=4 )
    #Attach to it using windbg
    attach( p, final_script )

    return p

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
    if isinstance(windbgscript, list):
        #tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.windbg',
        #                                  delete = False)
        #log.debug('Wrote windbgscript script to %r\n%s' % (tmp.name, windbgscript))
        #windbgscript = '.shell del %s\n%s' % (tmp.name, windbgscript)

        #tmp.write(windbgscript)
        #tmp.close()
        #cmd.append('$><%s' % (tmp.name))
        
        #Array vs file
        cmds = ";".join(windbgscript)
        cmd.append('-c')
        cmd.append(cmds)
    
    log.info("Launching a new process: %r" % cmd)
    p = subprocess.Popen( cmd, executable=cmd[0] )
    windbg_pid = p.pid

    if pid and context.native:
        proc.wait_for_debugger(pid)

    return windbg_pid

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

