"""
During exploit development, it is frequently useful to debug the
target binary under WinDbg. This module provides a simple interface
to do so under Windows.

Useful Functions
----------------

- :func:`attach` - Attach to an existing process

Debugging Tips
--------------

The :func:`attach` and :func:`debug` functions will likely be your bread and
butter for debugging.

Both allow you to provide a script to pass to WinDbg when it is started, so that
it can automatically set your breakpoints.

Attaching to Processes
~~~~~~~~~~~~~~~~~~~~~~

To attach to an existing process, just use :func:`attach`.  You can pass a PID,
a process name (including file extension), or a :class:`.process`.

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
(The name is borrowed from ptrace syscall on Linux.)

::

    $ python exploit.py NOPTRACE
    [+] Starting local process 'chall.exe': Done
    [!] Skipping debug attach since context.noptrace==True
    ...

Member Documentation
===============================
"""
from __future__ import absolute_import
import atexit
import os
import signal

import subprocess

from pwnlib import tubes
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import misc
from pwnlib.util import proc

log = getLogger(__name__)

CREATE_SUSPENDED = 0x00000004

@LocalContext
def debug(args, dbgscript=None, exe=None, env=None, creationflags=0, **kwargs):
    """debug(args, dbgscript=None, exe=None, env=None, creationflags=0) -> tube

    Launch a process in suspended state, attach debugger and resume process.

    Arguments:
        args(list): Arguments to the process, similar to :class:`.process`.
        dbgscript(str): windbg script to run.
        exe(str): Path to the executable on disk.
        env(dict): Environment to start the binary in.
        creationflags(int): Flags to pass to :func:`.process.process`.

    Returns:
        :class:`.process`: A tube connected to the target process.

    Notes:

        .. code-block: python

            # Create a new process, and stop it at 'main'
            io = windbg.debug('calc', '''
            bp $exentry
            g
            ''')

        When the debugger opens via :func:`.debug`, it will initially be stopped on the very first
        instruction of the entry point.
    """
    if isinstance(
        args, (int, tubes.process.process, tubes.ssh.ssh_channel)
    ):
        log.error("Use windbg.attach() to debug a running process")

    if context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return tubes.process.process(args, executable=exe, env=env, creationflags=creationflags)
    
    dbgscript = dbgscript or ''
    if isinstance(dbgscript, str):
        dbgscript = dbgscript.split('\n')
    # resume main thread
    dbgscript = ['~0m'] + dbgscript
    creationflags |= CREATE_SUSPENDED
    io = tubes.process.process(args, executable=exe, env=env, creationflags=creationflags)
    attach(target=io, dbgscript=dbgscript, **kwargs)

    return io

def binary():
    """binary() -> str

    Returns the path to the WinDbg binary.

    Returns:
        str: Path to the appropriate ``windbg`` binary to use.
    """
    windbg = misc.which('windbgx.exe') or misc.which('windbg.exe')
    if not windbg:
        log.error('windbg is not installed or in system PATH')
    return windbg

@LocalContext
def attach(target, dbgscript=None, dbg_args=[]):
    """attach(target, dbgscript=None, dbg_args=[]) -> int

    Attach to a running process with WinDbg.

    Arguments:
        target(int, str, process): Process to attach to.
        dbgscript(str, list): Debugger script to run after attaching.
        dbg_args(list): Additional arguments to pass to the debugger.

    Returns:
        int: PID of the debugger process.

    Notes:

        The ``target`` argument is very robust, and can be any of the following:

        :obj:`int`
            PID of a process
        :obj:`str`
            Process name.  The youngest process is selected.
        :class:`.process`
            Process to connect to
    
    Examples:

        Attach to a process by PID

        >>> pid = windbg.attach(1234) # doctest: +SKIP

        Attach to the youngest process by name

        >>> pid = windbg.attach('cmd.exe') # doctest: +SKIP

        Attach a debugger to a :class:`.process` tube and automate interaction

        >>> io = process('cmd') # doctest: +SKIP
        >>> pid = windbg.attach(io, dbgscript='''
        ... bp kernelbase!WriteFile
        ... g
        ... ''') # doctest: +SKIP
    """
    if context.noptrace:
        log.warn_once("Skipping debug attach since context.noptrace==True")
        return

    # let's see if we can find a pid to attach to
    pid = None
    if isinstance(target, int):
        # target is a pid, easy peasy
        pid = target
    elif isinstance(target, str):
        # pidof picks the youngest process
        pids = list(proc.pidof(target))
        if not pids:
            log.error('No such process: %s', target)
        pid = pids[0]
        log.info('Attaching to youngest process "%s" (PID = %d)' %
                 (target, pid))
    elif isinstance(target, tubes.process.process):
        pid = proc.pidof(target)[0]
    else:
        log.error("don't know how to attach to target: %r", target)

    if not pid:
        log.error('could not find target process')
    
    cmd = [binary()]
    if dbg_args:
        cmd.extend(dbg_args)
    
    cmd.extend(['-p', str(pid)])

    dbgscript = dbgscript or ''
    if isinstance(dbgscript, str):
        dbgscript = dbgscript.split('\n')
    if isinstance(dbgscript, list):
        dbgscript = ';'.join(script.strip() for script in dbgscript if script.strip())
    if dbgscript:
        cmd.extend(['-c', dbgscript])
    
    log.info("Launching a new process: %r" % cmd)

    io = subprocess.Popen(cmd)
    debugger_pid = io.pid

    def kill():
        try:
            os.kill(debugger_pid, signal.SIGTERM)
        except OSError:
            pass

    atexit.register(kill)

    if context.native:
        proc.wait_for_debugger(pid, debugger_pid)

    return debugger_pid
