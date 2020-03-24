import os
import msvcrt
import ctypes
import sys
from ctypes import wintypes

__all__ = ['get']

cache = None

def get(cap, *args, **kwargs):
    default = kwargs.pop('default', '')

    if 'PWNLIB_NOTERM' in os.environ:
        return default

    if kwargs != {}:
        raise TypeError("get(): No such argument %r" % kwargs.popitem()[0])

    if cache is None:
        init()
    
    s = cache.get(cap)
    if s:
        if args:
            return s(*args)
        return s
    return default

def init():
    global cache
    cache = {}

    if 'PWNLIB_NOTERM' not in os.environ:
        try:
            enable_vt_mode()
        except:
            # If the terminal doesn't support ANSI escape codes, don't use them.
            return

    # Setup capabilities similar to curses on unix.
    # https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
    cache['colors'] = 256
    cache['reset'] = '\x1b[0m'
    cache['bold'] = '\x1b[1m'
    cache['smul'] = '\x1b[4m'
    cache['rev'] = '\x1b[7m'
    cache['setaf'] = lambda c: '\x1b[3{}m'.format(c) if c < 8 else '\x1b[9{}m'.format(c-8)
    cache['setab'] = lambda c: '\x1b[4{}m'.format(c) if c < 8 else '\x1b[10{}m'.format(c-8)

# Enable ANSI escape sequences on Windows 10.
# https://bugs.python.org/issue30075
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

ERROR_INVALID_PARAMETER = 0x0057
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

def _check_bool(result, func, args):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return args

LPDWORD = ctypes.POINTER(wintypes.DWORD)
kernel32.GetConsoleMode.errcheck = _check_bool
kernel32.GetConsoleMode.argtypes = (wintypes.HANDLE, LPDWORD)
kernel32.SetConsoleMode.errcheck = _check_bool
kernel32.SetConsoleMode.argtypes = (wintypes.HANDLE, wintypes.DWORD)

def set_conout_mode(new_mode, mask=0xffffffff):
    # don't assume StandardOutput is a console.
    # open CONOUT$ instead
    fdout = os.open('CONOUT$', os.O_RDWR)
    try:
        hout = msvcrt.get_osfhandle(fdout)
        old_mode = wintypes.DWORD()
        kernel32.GetConsoleMode(hout, ctypes.byref(old_mode))
        mode = (new_mode & mask) | (old_mode.value & ~mask)
        kernel32.SetConsoleMode(hout, mode)
        return old_mode.value
    finally:
        os.close(fdout)

def enable_vt_mode():
    mode = mask = ENABLE_VIRTUAL_TERMINAL_PROCESSING
    try:
        return set_conout_mode(mode, mask)
    except WindowsError as e:
        if e.winerror == ERROR_INVALID_PARAMETER:
            raise NotImplementedError
        raise
