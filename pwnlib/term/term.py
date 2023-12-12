from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import atexit
import errno
import os
import re
import shutil
import signal
import struct
import sys
import threading
import traceback
import weakref

if sys.platform != 'win32':
    import fcntl
    import termios

from ..context import ContextType
from . import termcap
from .. import py2compat

__all__ = ['output', 'init']

# we assume no terminal can display more lines than this
MAX_TERM_HEIGHT = 200

# list of callbacks triggered on SIGWINCH
on_winch = []

cached_pos = None
settings = None
setup_done = False
epoch = 0

fd = sys.stdout
winchretry = False
rlock = threading.RLock()

class WinchLock(object):
    def __init__(self):
        self.guard = threading.RLock()
        self.lock = threading.Lock()

    @property
    def acquire(self):
        return self.lock.acquire

    @property
    def release(self):
        return self.lock.release

    def __enter__(self):
        self.guard.acquire()
        return self.lock.__enter__()
    def __exit__(self, tp, val, tb):
        try:
            return self.lock.__exit__(tp, val, tb)
        finally:
            if winchretry:
                handler_sigwinch(signal.SIGWINCH, None)
            self.guard.release()

wlock = WinchLock()

def show_cursor():
    do('cnorm')

def hide_cursor():
    do('civis')

def update_geometry():
    global width, height
    width, height = shutil.get_terminal_size()

def handler_sigwinch(signum, stack):
    global cached_pos, winchretry
    with wlock.guard:
        while True:
            if not wlock.acquire(False):
                winchretry = True
                return

            winchretry = False
            update_geometry()
            for cb in on_winch:
                cb()
            wlock.release()
            if not winchretry: break


def handler_sigstop(signum, stack):
    resetterm()
    os.kill(0, signal.SIGSTOP)

def handler_sigcont(signum, stack):
    global epoch, cached_pos, setup_done
    epoch += 1
    cached_pos = None
    setup_done = False

def setupterm():
    global settings, setup_done
    if setup_done:
        return
    setup_done = True
    hide_cursor()
    update_geometry()
    do('smkx') # keypad mode
    mode = termios.tcgetattr(fd)
    IFLAG, OFLAG, CFLAG, LFLAG, ISPEED, OSPEED, CC = range(7)
    if not settings:
        settings = mode[:]
        settings[CC] = settings[CC][:]
    mode[LFLAG] &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN)
    mode[CC][termios.VMIN] = 1
    mode[CC][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSADRAIN, mode)
    fd.flush()

def resetterm():
    global settings, setup_done
    if settings:
        termios.tcsetattr(fd, termios.TCSADRAIN, settings)
        settings = None
    if setup_done:
        setup_done = False
        show_cursor()
        do('rmkx')
        fd.flush()

def init():
    atexit.register(resetterm)
    signal.signal(signal.SIGWINCH, handler_sigwinch)
    signal.signal(signal.SIGTSTP, handler_sigstop)
    signal.signal(signal.SIGCONT, handler_sigcont)
    class Wrapper:
        def __init__(self, fd):
            self._fd = fd
        def write(self, s):
            return output(s, frozen=True)
        def __getattr__(self, k):
            return getattr(self._fd, k)
    if sys.stdout.isatty():
        sys.stdout = Wrapper(sys.stdout)
    if sys.stderr.isatty():
        sys.stderr = Wrapper(sys.stderr)

    console = ContextType.defaults['log_console']
    if console.isatty():
        ContextType.defaults['log_console'] = Wrapper(console)

    # freeze all cells if an exception is thrown
    orig_hook = sys.excepthook
    def hook(*args):
        sys.stderr = sys.__stderr__
        resetterm()
        cells.clear()
        if orig_hook:
            orig_hook(*args)
        else:
            traceback.print_exception(*args)
    sys.excepthook = hook

tmap = {c: '\\x{:02x}'.format(c) for c in set(range(0x20)) - {0x09, 0x0a, 0x0d, 0x1b} | {0x7f}}

def put(s):
    global cached_pos, epoch
    s = s.translate(tmap)
    if cached_pos:
        it = iter(s.replace('\n', '\r\n'))
        sanit_s = ''
        for c in it:
            if c == '\r':
                cached_pos[1] = 0
            elif c == '\n':
                cached_pos[0] += 1
            elif c == '\t':
                cached_pos[1] = (cached_pos[1] + 8) & -8
            elif c in '\x1b\u009b':  # ESC or CSI
                seq = c
                for c in it:
                    seq += c
                    if c not in '[0123456789;':
                        break
                else:
                    # unterminated ctrl seq, just print it visually
                    c = seq.replace('\x1b', r'\x1b').replace('\u009b', r'\u009b')
                    cached_pos[1] += len(c)

                # if '\e[123;123;123;123m' then nothing
                if c == 'm':
                    c = seq
                else:
                    # undefined ctrl seq, just print it visually
                    c = seq.replace('\x1b', r'\x1b').replace('\u009b', r'\u009b')
                    cached_pos[1] += len(c)
            elif c < ' ':
                assert False, 'impossible ctrl char'
            else:
                # normal character, nothing to see here
                cached_pos[1] += 1
            sanit_s += c
        else:
            s = sanit_s.replace('\r\n', '\n')
    return fd.write(s)

def do(c, *args):
    s = termcap.get(c, *args)
    if s:
        fd.write(s.decode('utf-8'))

def goto(rc):
    global cached_pos
    r, c = rc
    nowr, nowc = cached_pos or (None, None)
    cached_pos = [r, c]
    # common cases: we can just go up/down a couple rows
    if c == 0:
        if r == nowr + 1:
            fd.write('\n')
            return
        if c != nowc:
            fd.write('\r')
    elif c != nowc:
        do('hpa', c)

    if r == nowr - 1:
        do('cuu1')
    elif r < nowr:
        do('cuu', nowr - r)
    elif r > nowr:
        do('cud', r - nowr)


class Cell(object):
    def __init__(self, value, float):
        self.value = value
        self.float = float

    def draw(self):
        self.pos = get_position()
        self.born = epoch
        put(self.value)
        self.pos_after = get_position()

    def update(self, value):
        if isinstance(value, bytes):
            value = value.decode('utf-8', 'backslashreplace')
        with wlock:
            want_erase_line = False
            if '\n' in value:
                if len(value) < len(self.value):
                    want_erase_line = True
                elif '\n' not in self.value:  # not really supported
                    for cell in cells.iter_after(self):
                        if cell.value:
                            want_erase_line = True
                        break
            self.value = value
            self.update_locked(erase_line=want_erase_line)
            fd.flush()

    def prepare_redraw(self):
        global epoch
        if self.born != epoch:
            return None
        saved = get_position()
        if saved < self.pos or saved == (1, 1):
            epoch += 1
            return None
        goto(self.pos)
        return saved

    def update_locked(self, erase_line=False):
        prev_pos = self.prepare_redraw()
        if prev_pos is None:
            for cell in cells:
                cell.draw()
            return
        erased_line = None
        if erase_line:
            do('el')
            erased_line = self.pos[0]
        put(self.value)
        pos = get_position()
        if pos == self.pos_after:
            goto(prev_pos)
            return
        if pos < self.pos_after:
            do('el')
            erased_line = self.pos[0]
        old_after = self.pos_after
        self.pos_after = pos

        cell = self  # in case there are no more cells
        for cell in cells.iter_after(self):
            if old_after != cell.pos:
                # do not merge gaps
                break
            pos = get_position()
            if erased_line != pos[0]:
                if pos[0] < cell.pos[0]:
                    # the cell moved up, erase its line
                    do('el')
                    erased_line = pos[0]
                elif cell.pos == pos:
                    # cell got neither moved nor erased
                    break

            if pos[1] < cell.pos[1]:
                # the cell moved left, it must be same line as self; erase if not yet erased
                if not erase_line and erased_line != pos[0]:
                    do('el')
                    erased_line = pos[0]

            old_after = cell.pos_after
            cell.draw()
            if cell.pos_after == old_after and erased_line != old_after[0]:
                break
        else:
            if cell.float:
                # erase all screen after last float
                do('ed')
        if prev_pos > get_position():
            goto(prev_pos)

    def __repr__(self):
        return '{}({!r}, float={}, pos={})'.format(self.__class__.__name__, self.value, self.float, self.pos)


class WeakCellList(object):
    def __init__(self):
        self._cells = []
        self._floats = []
        self._lists = self._cells, self._floats

    @property
    def cells(self):
        return self.iter_field(self._cells)

    @property
    def floats(self):
        return self.iter_field(self._floats)

    def iter_field(self, *Ls):
        for L in Ls:
            for iref in L[:]:
                i = iref()
                if i is None:
                    L.remove(iref)
                else:
                    yield i

    def __iter__(self):
        return self.iter_field(*self._lists)

    def iter_after(self, v):
        it = iter(self)
        for cell in it:
            if cell == v:
                break
        return it

    def clear(self):
        for c in self:
            c.float = False
        for L in self._lists:
            del L[:]

    def insert(self, v, before):
        L = self._lists[v.float]
        for i, e in enumerate(self.iter_field(L)):
            if e == before:
                L.insert(i, weakref.ref(v))
                return
        raise IndexError('output before dead cell')

    def append(self, v):
        L = self._lists[v.float]
        L.append(weakref.ref(v))


cells = WeakCellList()


def get_position():
    global cached_pos
    if not cached_pos:
        cached_pos = [0, 0]
    return tuple(cached_pos)


def output(s='', float=False, priority=10, frozen=False, indent=0, before=None):
    with wlock:
        if before:
            float = before.float

        if isinstance(s, bytes):
            s = s.decode('utf-8', 'backslashreplace')
        if frozen:
            for f in cells.floats:
                f.prepare_redraw()
                do('ed')  # we could do it only when necessary
                break
            ret = put(s)
            for f in cells.floats:
                f.draw()
            for f in cells.floats:
                fd.flush()
                break
            return ret

        c = Cell(s, float)
        if before is None:
            cells.append(c)
            c.draw()
        else:
            before.prepare_redraw()
            cells.insert(c, before)
            c.draw()
            for f in cells.iter_after(c):
                f.draw()
        return c
