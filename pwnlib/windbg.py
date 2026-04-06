"""
During exploit development, it is frequently useful to debug the
target binary under WinDbg. This module provides a simple interface
to do so under Windows.

By default, :attr:`.context.debugger` is set to ``"auto"``, which will
attempt to automatically select an appropriate debugger based on the
available debuggers on the system.

The order of preference is:
- ``windbgx``
- ``windbg``

If automatic lookup fails, you can manually set :attr:`.context.debugger` to
the debugger of your choice and provide the path to the debugger binary
using :attr:`.context.windbgx_binary` or :attr:`.context.windbg_binary`.

Useful Functions
----------------

- :func:`attach` - Attach to an existing process
- :func:`debug` - Start a new process under the debugger

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
import atexit
import os
import signal

import subprocess
import tempfile

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

    Returns the path to the debugger binary depending on the context.
    :attr:`.context.debugger` is used to determine which debugger to use.

    Returns:
        str: Path to the appropriate ``windbg`` binary to use.
    """
    if context.debugger == 'auto':
        for debugger in context.debugger_choices:
            with context.local(debugger=debugger, log_level='critical'):
                try:
                    return binary()
                except Exception:
                    pass
        else:
            log.error('No debugger found. Please set context.debugger to one of: %s\n'
                      'You might have to specify the path to the debugger binary with context.windbg_binary or context.windbgx_binary.',
                      ', '.join(context.debugger_choices))
    
    if context.debugger == 'windbg':
        if context.windbg_binary:
            windbg = misc.which(context.windbg_binary)
            if not windbg:
                log.warn_once('Path to WinDbg binary `{}` not found'.format(context.windbg_binary))
            return windbg

        windbg = misc.which('windbg.exe')
        if not windbg and os.environ.get('ProgramFiles(x86)'):
            arch_str = {
                'i386': 'x86',
                'amd64': 'x64',
                'aarch64': 'arm64',
            }.get(context.arch)
            if not arch_str:
                log.error('Unsupported architecture for windbg: {}'.format(context.arch))
            windbg = os.path.join(os.environ.get('ProgramFiles(x86)'), 'Windows Kits', '10', 'Debuggers', arch_str, 'windbg.exe')
        if not windbg or not os.path.exists(windbg):
            log.error('windbg is not installed or in system PATH. You can set context.windbg_binary to specify the path manually.')
        return windbg

    if context.debugger == 'windbgx':
        if context.windbgx_binary:
            windbg = misc.which(context.windbgx_binary)
            if not windbg:
                log.warn_once('Path to WinDbgx binary `{}` not found'.format(context.windbgx_binary))
            return windbg

        windbg = misc.which('windbgx.exe')
        if not windbg and os.environ.get('LocalAppData'):
            windbg = os.path.join(os.environ.get('LocalAppData'), 'Microsoft', 'WindowsApps', 'WinDbgX.exe')
        if not windbg or not os.path.exists(windbg):
            log.error('windbgx is not installed or in system PATH. You can set context.windbgx_binary to specify the path manually.')
        return windbg

    log.error('Invalid debugger selection: %s', context.debugger)

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
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.dbg') as tmp:
        tmp.write('\n'.join(script.strip() for script in dbgscript if script.strip()))
        tmp.flush()
        dbgscript_file = tmp.name
    
    if dbgscript:
        cmd.extend(['-c', '$<{}'.format(dbgscript_file)])
    
    log.info("Launching a new process: %r" % cmd)

    io = subprocess.Popen(cmd)
    debugger_pid = io.pid

    def kill():
        try:
            os.unlink(dbgscript_file)
            os.kill(debugger_pid, signal.SIGTERM)
        except OSError:
            pass

    atexit.register(kill)

    if context.native:
        proc.wait_for_debugger(pid, debugger_pid)

    return debugger_pid
