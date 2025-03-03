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

import six

from pwnlib import tubes
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import misc
from pwnlib.util import proc

log = getLogger(__name__)

CREATE_SUSPENDED = 0x00000004

@LocalContext
def debug(args, windbgscript=None, exe=None, env=None, creationflags=0, **kwargs):
    """debug(args, windbgscript=None, exe=None, env=None, creationflags=0) -> tube

    Launch a process in suspended state, attach debugger and resume process.

    Arguments:
        args(list): Arguments to the process, similar to :class:`.process`.
        windbgscript(str): windbg script to run.
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
            go
            ''')

        When WinDbg opens via :func:`.debug`, it will initially be stopped on the very first
        instruction of the entry point.
    """
    if isinstance(
        args, six.integer_types + (tubes.process.process, tubes.ssh.ssh_channel)
    ):
        log.error("Use windbg.attach() to debug a running process")

    if context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return tubes.process.process(args, executable=exe, env=env, creationflags=creationflags)
    
    windbgscript = windbgscript or ''
    if isinstance(windbgscript, six.string_types):
        windbgscript = windbgscript.split('\n')
    # resume main thread
    windbgscript = ['~0m'] + windbgscript
    creationflags |= CREATE_SUSPENDED
    io = tubes.process.process(args, executable=exe, env=env, creationflags=creationflags)
    attach(target=io, windbgscript=windbgscript, **kwargs)

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
def attach(target, windbgscript=None, windbg_args=[]):
    """attach(target, windbgscript=None, windbg_args=[]) -> int

    Attach to a running process with WinDbg.

    Arguments:
        target(int, str, process): Process to attach to.
        windbgscript(str, list): WinDbg script to run after attaching.
        windbg_args(list): Additional arguments to pass to WinDbg.

    Returns:
        int: PID of the WinDbg process.

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
        >>> pid = windbg.attach(io, windbgscript='''
        ... bp kernelbase!WriteFile
        ... g
        ... ''') # doctest: +SKIP
    """
    if context.noptrace:
        log.warn_once("Skipping debug attach since context.noptrace==True")
        return

    # let's see if we can find a pid to attach to
    pid = None
    if isinstance(target, six.integer_types):
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
    if windbg_args:
        cmd.extend(windbg_args)
    
    cmd.extend(['-p', str(pid)])

    windbgscript = windbgscript or ''
    if isinstance(windbgscript, six.string_types):
        windbgscript = windbgscript.split('\n')
    if isinstance(windbgscript, list):
        windbgscript = ';'.join(script.strip() for script in windbgscript if script.strip())
    if windbgscript:
        cmd.extend(['-c', windbgscript])
    
    log.info("Launching a new process: %r" % cmd)

    io = subprocess.Popen(cmd)
    windbg_pid = io.pid

    def kill():
        try:
            os.kill(windbg_pid, signal.SIGTERM)
        except OSError:
            pass

    atexit.register(kill)

    if context.native:
        proc.wait_for_debugger(pid, windbg_pid)

    return windbg_pid
