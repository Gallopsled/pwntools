from __future__ import absolute_import
from __future__ import division

import atexit
import errno
import os
import re
import shutil
import signal
import six
import struct
import sys
import threading
import traceback
import weakref

if sys.platform != 'win32':
    import fcntl
    import termios

from pwnlib.context import ContextType
from pwnlib.term import termcap

__all__ = ['output', 'init']

# we assume no terminal can display more lines than this
MAX_TERM_HEIGHT = 200

# default values
scroll = 0

# list of callbacks triggered on SIGWINCH
on_winch = []

cached_pos = None
settings = None
epoch = 0

fd = sys.stdout
winchretry = []
rlock = threading.RLock()

class WinchLock(object):
    def __init__(self):
        self.lock = threading.Lock()

    @property
    def acquire(self):
        return self.lock.acquire

    @property
    def release(self):
        return self.lock.release

    def __enter__(self):
        return self.lock.__enter__()
    def __exit__(self, tp, val, tb):
        #open('cellz.log', 'a').write(repr(list(cells)) + '\n')
        try:
            return self.lock.__exit__(tp, val, tb)
        finally:
            try:
                winchretry.pop()
            except IndexError:
                pass
            else:
                handler_sigwinch(signal.SIGWINCH, None)

winchlock = WinchLock()

def show_cursor():
    do('cnorm')

def hide_cursor():
    do('civis')

def update_geometry():
    global width, height
    width, height = shutil.get_terminal_size()

def handler_sigwinch(signum, stack):
    global cached_pos
    with rlock:
        while True:
            if not winchlock.acquire(False):
                winchretry.append(0)
                return

            cached_pos = None
            update_geometry()
            for cb in on_winch:
                cb()
            winchlock.release()
            try:
                winchretry.pop()
            except IndexError:
                break
            del winchretry[:]


def handler_sigstop(signum, stack):
    resetterm()
    os.kill(os.getpid(), signal.SIGSTOP)

def handler_sigcont(signum, stack):
    global epoch, cached_pos, scroll
    epoch += 1
    cached_pos = None
    scroll = 0
    setupterm()

def setupterm():
    global settings
    hide_cursor()
    update_geometry()
    do('smkx') # keypad mode
    mode = termios.tcgetattr(fd.fileno())
    IFLAG, OFLAG, CFLAG, LFLAG, ISPEED, OSPEED, CC = range(7)
    if not settings:
        settings = mode[:]
        settings[CC] = settings[CC][:]
    mode[LFLAG] &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN)
    mode[CC][termios.VMIN] = 1
    mode[CC][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSADRAIN, mode)

def resetterm():
    if settings:
        termios.tcsetattr(fd.fileno(), termios.TCSADRAIN, settings)
    show_cursor()
    do('rmkx')
    fd.write(' \x08') # XXX: i don't know why this is needed...
                      #      only necessary when suspending the process
    fd.flush()

def init():
    atexit.register(resetterm)
    setupterm()
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
        resetterm()
        for c in cells:
            c.frozen = True
            c.float = 0
        if orig_hook:
            orig_hook(*args)
        else:
            traceback.print_exception(*args)
        # this is a bit esoteric
        # look here for details: https://stackoverflow.com/questions/12790328/how-to-silence-sys-excepthook-is-missing-error
        if fd.fileno() == 2:
            os.close(fd.fileno())
    sys.excepthook = hook

tmap = {c: '\\x{:02x}'.format(c) for c in set(range(0x20)) - {0x09, 0x0a, 0x0d, 0x1b} | {0x7f}}

def put(s):
    global cached_pos, scroll
    if cached_pos:
        it = iter(s.replace('\n', '\r\n'))
        for c in it:
            if c == '\r':
                cached_pos[1] = 0
            elif c == '\n':
                cached_pos[0] += 1
                if cached_pos[0] >= height:
                    scroll = max(scroll, cached_pos[0] - height + 1)
            elif c == '\t':
                cached_pos[1] = (cached_pos[1] + 8) & -8
            elif c in '\x1b\u009b':  # ESC or CSI
                for c in it:
                    if c not in '[]0123456789;:':
                        break
                else:
                    # unterminated ctrl seq, just discard cache
                    cached_pos = None
                    break

                # if '\e[123;123;123;123m' then nothing
                if c == 'm':
                    pass
                else:
                    # undefined ctrl seq, just discard cache
                    cached_pos = None
                    break
            elif c < ' ':
                # undefined ctrl char, just discard cache
                cached_pos = None
                break
            else:
                # normal character, nothing to see here
                cached_pos[1] += 1
    fd.write(s.translate(tmap))

def flush(): fd.flush()

def do(c, *args):
    s = termcap.get(c, *args)
    if s:
        fd.write(s.decode('utf-8'))

def goto(rc):
    global cached_pos
    r, c = rc
    nowr, nowc = cached_pos or (-999, -999)
    cached_pos = [r, c]
    if nowc == c:
        # common case: we can just go up/down a couple rows
        if r == nowr - 1:
            do('cuu1')
        elif r == nowr + 1:
            do('cud1')
        elif r < nowr:
            do('cuu', nowr - r)
        elif r > nowr:
            do('cud', r - nowr)
    else:
        do('cup', r - scroll, c)


class Cell(object):
    def __init__(self, value, float, priority):
        self.value = value
        self.float = float

    def draw(self):
        self.pos = get_position()
        self.born = epoch
        #put('{' + self.value.replace('\33', 'E').replace('', '.') + '}')
        put(self.value)

    def update(self, value):
        with rlock, winchlock:
            el = len(value) < len(self.value)
            self.value = value
            self.update_locked(el=el)

    def update_locked(self, goto_only=False, el=False):
        global epoch
        if self.born != epoch:
            if goto_only: return
            for cell in cells:
                cell.draw()
        else:
            saved = get_position()
            if saved < self.pos or saved == (1, 1):
                epoch += 1
                if goto_only: return
                for cell in cells:
                    cell.draw()
                flush()
                return
            goto(self.pos)
            if goto_only: return
            if el:
                do('el')
            #put('{' + self.value.replace('\33', 'E').replace('', '.') + '}')
            put(self.value)
            it = iter(cells)
            for cell in it:
                if cell == self:
                    break
            for cell in it:
                pos = get_position()
                if cell.pos == pos and (not el or pos[0] != self.pos[0]):
                    break
                if pos[1] < cell.pos[1] and not el:
                    do('el')
                    el = True
                cell.draw()
            else:
                if cell.float:
                    do('ed')
            if saved > get_position():
                goto(saved)
        flush()
    def __repr__(self):
        return '{}({!r}, float={}, pos={})'.format(self.__class__.__name__, self.value, self.float, self.pos)


class WeakCellList(object):
    def __init__(self):
        self.cells = []
        self.floats = []

    def iter_field(self, *Ls):
        for L in Ls:
            for iref in L[:]:
                i = iref()
                if i is None:
                    L.remove(iref)
                else:
                    yield i

    def __iter__(self):
        return self.iter_field(self.cells, self.floats)

    def insert(self, v, before):
        if v.float:
            for i, e in enumerate(self.iter_field(self.floats)):
                if e == before:
                    self.floats.insert(i, weakref.ref(v))
                    return
        else:
            for i, e in enumerate(self.iter_field(self.cells)):
                if e == before:
                    self.cells.insert(i, weakref.ref(v))
                    return
            for e in self.iter_field(self.floats):
                if e == before:
                    self.cells.append(weakref.ref(v))
                    return
                break
        raise IndexError(f'output({v=}, {before=})')

    def append(self, v):
        if v.float:
            self.floats.append(weakref.ref(v))
        else:
            self.cells.append(weakref.ref(v))


cells = WeakCellList()


def get_position():
    global cached_pos
    if cached_pos:
        return tuple(cached_pos)

    #do('u7')
    fd.write('\x1b[6n')
    fd.flush()
    s = os.read(fd.fileno(), 6)
    while True:
        if s[-1:] == b'R':
            mat = re.findall(b'\x1b' + br'\[(\d*);(\d*)R', s)
            if mat:
                [[row, col]] = mat
                break
        try:
            s += os.read(fd.fileno(), 1)
        except OSError as e:
            if e.errno != errno.EINTR:
                raise
            continue
    row = int(row) + scroll - 1
    col = int(col) - 1
    cached_pos = [row, col]
    return tuple(cached_pos)


def output(s='', float=False, priority=10, frozen=False, indent=0, before=None):
    with rlock, winchlock:
        if isinstance(s, bytes):
            s = s.decode('utf-8', 'backslashreplace')
        if frozen:
            for f in cells.iter_field(cells.floats):
                f.update_locked(goto_only=True)
                break
            ret = put(s)
            for f in cells.iter_field(cells.floats):
                f.draw()
            return ret

        c = Cell(s, float, priority)
        if before is None:
            cells.append(c)
            c.draw()
        else:
            before.update_locked(goto_only=True)
            cells.insert(c, before)
            c.draw()
            it = iter(cells)
            for f in it:
                if f == c:
                    break
            for f in it:
                f.draw()
        return c
