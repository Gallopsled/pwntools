__all__ = ['output', 'init']

# we assume no terminal can display more lines than this
MAX_TERM_HEIGHT = 200

# default values
width = 80
height = 25

# list of callbacks triggered on SIGWINCH
on_winch = []

import atexit
import fcntl
import os
import re
import signal
import struct
import sys
import termios
import threading
import traceback

from . import termcap

settings = None
_graphics_mode = False

fd = sys.stdout

def show_cursor():
    do('cnorm')

def hide_cursor():
    do('civis')

def update_geometry():
    global width, height
    hw = fcntl.ioctl(fd.fileno(), termios.TIOCGWINSZ, '1234')
    h, w = struct.unpack('hh', hw)
    # if the window shrunk and theres still free space at the bottom move
    # everything down
    if h < height and scroll == 0:
        if cells and cells[-1].end[0] < 0:
            delta = min(height - h, 1 - cells[-1].end[0])
            for cell in cells:
                cell.end = (cell.end[0] + delta, cell.end[1])
                cell.start = (cell.start[0] + delta, cell.start[1])
    height, width = h, w

def handler_sigwinch(signum, stack):
    update_geometry()
    redraw()
    for cb in on_winch:
        cb()

def handler_sigstop(signum, stack):
    resetterm()
    os.kill(os.getpid(), signal.SIGSTOP)

def handler_sigcont(signum, stack):
    setupterm()
    redraw()

def setupterm():
    global settings
    update_geometry()
    hide_cursor()
    do('smkx') # keypad mode
    if not settings:
        settings = termios.tcgetattr(fd.fileno())
    mode = termios.tcgetattr(fd.fileno())
    IFLAG = 0
    OFLAG = 1
    CFLAG = 2
    LFLAG = 3
    ISPEED = 4
    OSPEED = 5
    CC = 6
    mode[LFLAG] = mode[LFLAG] & ~(termios.ECHO | termios.ICANON | termios.IEXTEN)
    mode[CC][termios.VMIN] = 1
    mode[CC][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSAFLUSH, mode)

def resetterm():
    if settings:
        termios.tcsetattr(fd.fileno(), termios.TCSADRAIN, settings)
    show_cursor()
    do('rmkx')
    fd.write(' \x08') # XXX: i don't know why this is needed...
                      #      only necessary when suspending the process

def init():
    atexit.register(resetterm)
    setupterm()
    signal.signal(signal.SIGWINCH, handler_sigwinch)
    signal.signal(signal.SIGTSTP, handler_sigstop)
    signal.signal(signal.SIGCONT, handler_sigcont)
    # we start with one empty cell at the current cursor position
    put('\x1b[6n')
    fd.flush()
    s = ''
    while True:
        c = os.read(fd.fileno(), 1)
        s += c
        if c == 'R':
            break
    row, col = re.findall('\x1b' + r'\[(\d*);(\d*)R', s)[0]
    row = int(row) - height
    col = int(col) - 1
    cell = Cell()
    cell.start = (row, col)
    cell.end = (row, col)
    cell.content = []
    cell.frozen = True
    cell.float = 0
    cell.indent = 0
    cells.append(cell)
    class Wrapper:
        def __init__(self, fd):
            self._fd = fd
        def write(self, s):
            output(s, frozen = True)
        def __getattr__(self, k):
            return self._fd.__getattribute__(k)
    if sys.stdout.isatty():
        sys.stdout = Wrapper(sys.stdout)
    if sys.stderr.isatty():
        sys.stderr = Wrapper(sys.stderr)
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

def put(s):
    fd.write(s)

def flush(): fd.flush()

def do(c, *args):
    s = termcap.get(c, *args)
    if s:
        put(s)

def goto((r, c)):
    do('cup', r - scroll + height - 1, c)

cells = []
scroll = 0

class Cell(object):
    pass

class Handle:
    def __init__(self, cell, is_floating):
        self.h = id(cell)
        self.is_floating = is_floating
    def update(self, s):
        update(self.h, s)
    def freeze(self):
        freeze(self.h)
    def delete(self):
        delete(self.h)

STR, CSI, LF, BS, CR, SOH, STX, OOB = range(8)
def parse_csi(buf, offset):
    i = offset
    while i < len(buf):
        c = buf[i]
        if c >= 0x40 and c < 0x80:
            break
        i += 1
    if i >= len(buf):
        return
    end = i
    cmd = [c, None, None]
    i = offset
    in_num = False
    args = []
    if buf[i] >= ord('<') and buf[i] <= ord('?'):
        cmd[1] = buf[i]
        i += 1
    while i < end:
        c = buf[i]
        if   c >= ord('0') and c <= ord('9'):
            if not in_num:
                args.append(c - ord('0'))
                in_num = True
            else:
                args[-1] = args[-1] * 10 + c - ord('0')
        elif c == ord(';'):
            if not in_num:
                args.append(None)
            in_num = False
            if len(args) > 16:
                break
        elif c >= 0x20 and c <= 0x2f:
            cmd[2] = c
            break
        i += 1
    return cmd, args, end + 1

def parse_utf8(buf, offset):
    c0 = buf[offset]
    n = 0
    if   c0 & 0b11100000 == 0b11000000:
        n = 2
    elif c0 & 0b11110000 == 0b11100000:
        n = 3
    elif c0 & 0b11111000 == 0b11110000:
        n = 4
    elif c0 & 0b11111100 == 0b11111000:
        n = 5
    elif c0 & 0b11111110 == 0b11111100:
        n = 6
    if n:
        return offset + n

def parse(s):
    global _graphics_mode
    if isinstance(s, unicode):
        s = s.encode('utf8')
    out = []
    buf = map(ord, s)
    i = 0
    while True:
        if i >= len(buf):
            break
        x = None
        c = buf[i]
        if c >= 0x20 and c <= 0x7e:
            x = (STR, [chr(c)])
            i += 1
        elif c & 0xc0:
            j = parse_utf8(buf, i)
            if j:
                x = (STR, [''.join(map(chr, buf[i : j]))])
                i = j
        elif c == 0x1b and len(buf) > i + 1:
            c1 = buf[i + 1]
            if   c1 == ord('['):
                ret = parse_csi(buf, i + 2)
                if ret:
                    cmd, args, j = ret
                    x = (CSI, (cmd, args, ''.join(map(chr, buf[i : j]))))
                    i = j
            elif c1 == ord(']'):
                # XXX: this is a dirty hack:
                #  we still need to do our homework on this one, but what we do
                #  here is supporting setting the terminal title and updating
                #  the color map.  we promise to do it properly in the next
                #  iteration of this terminal emulation/compatibility layer
                #  related: https://unix.stackexchange.com/questions/5936/can-i-set-my-local-machines-terminal-colors-to-use-those-of-the-machine-i-ssh-i
                try:
                    j = s.index('\x07', i)
                except Exception:
                    try:
                        j = s.index('\x1b\\', i)
                    except Exception:
                        j = 1
                x = (OOB, s[i:j + 1])
                i = j + 1
            elif c1 in map(ord, '()'): # select G0 or G1
                i += 3
                continue
            elif c1 in map(ord, '>='): # set numeric/application keypad mode
                i += 2
                continue
            elif c1 == ord('P'):
                _graphics_mode = True
                i += 2
                continue
            elif c1 == ord('\\'):
                _graphics_mode = False
                i += 2
                continue
        elif c == 0x01:
            x = (SOH, None)
            i += 1
        elif c == 0x02:
            x = (STX, None)
            i += 1
        elif c == 0x08:
            x = (BS, None)
            i += 1
        elif c == 0x09:
            x = (STR, ['    ']) # who the **** uses tabs anyway?
            i += 1
        elif c == 0x0a:
            x = (LF, None)
            i += 1
        elif c == 0x0d:
            x = (CR, None)
            i += 1
        if _graphics_mode:
            continue
        if x is None:
            x = (STR, [c for c in '\\x%02x' % c])
            i += 1
        if x[0] == STR and out and out[-1][0] == STR:
            out[-1][1].extend(x[1])
        else:
            out.append(x)
    return out

saved_cursor = None
# XXX: render cells that is half-way on the screen
def render_cell(cell, clear_after = False):
    global scroll, saved_cursor
    row, col = cell.start
    row = row - scroll + height - 1
    if row < 0:
        return
    indent = min(cell.indent, width - 1)
    for t, x in cell.content:
        if   t == STR:
            i = 0
            while i < len(x):
                if col >= width:
                    col = 0
                    row += 1
                if col < indent:
                    put(' ' * (indent - col))
                    col = indent
                c = x[i]
                put(c)
                col += 1
                i += 1
        elif t == CSI:
            cmd, args, c = x
            put(c)
            # figure out if the cursor moved (XXX: here probably be bugs)
            if cmd[1] is None and cmd[2] is None:
                c = cmd[0]
                if len(args) >= 1:
                    n = args[0]
                else:
                    n = None
                if len(args) >= 2:
                    m = args[1]
                else:
                    m = None
                if   c == ord('A'):
                    n = n or 1
                    row = max(0, row - n)
                elif c == ord('B'):
                    n = n or 1
                    row = min(height - 1, row + n)
                elif c == ord('C'):
                    n = n or 1
                    col = min(width - 1, col + n)
                elif c == ord('D'):
                    n = n or 1
                    col = max(0, col - n)
                elif c == ord('E'):
                    n = n or 1
                    row = min(height - 1, row + n)
                    col = 0
                elif c == ord('F'):
                    n = n or 1
                    row = max(0, row - n)
                    col = 0
                elif c == ord('G'):
                    n = n or 1
                    col = min(width - 1, n - 1)
                elif c == ord('H') or c == ord('f'):
                    n = n or 1
                    m = m or 1
                    row = min(height - 1, n - 1)
                    col = min(width - 1, m - 1)
                elif c == ord('S'):
                    n = n or 1
                    scroll += n
                    row = max(0, row - n)
                elif c == ord('T'):
                    n = n or 1
                    scroll -= n
                    row = min(height - 1, row + n)
                elif c == ord('s'):
                    saved_cursor = row, col
                elif c == ord('u'):
                    if saved_cursor:
                        row, col = saved_cursor
        elif t == LF:
            if clear_after and col <= width - 1:
                put('\x1b[K') # clear line
            put('\n')
            col = 0
            row += 1
        elif t == BS:
            if col > 0:
                put('\x08')
                col -= 1
        elif t == CR:
#            put('\r')
            col = 0
        elif t == SOH:
            put('\x01')
        elif t == STX:
            put('\x02')
        elif t == OOB:
            put(x)
        if row >= height:
            d = row - height + 1
            scroll += d
            row -= d
    row = row + scroll - height + 1
    cell.end = (row, col)

def render_from(i, force = False, clear_after = False):
    e = None
    # `i` should always be a valid cell, but in case i f***ed up somewhere, I'll
    # check it and just do nothing if something went wrong.
    if i < 0 or i >= len(cells):
        return
    goto(cells[i].start)
    for c in cells[i:]:
        if not force and c.start == e:
            goto(cells[-1].end)
            break
        elif e:
            c.start = e
        render_cell(c, clear_after = clear_after)
        e = c.end
    if clear_after and (e[0] < scroll or e[1] < width - 1):
        put('\x1b[J')
    flush()

def redraw():
    for i in reversed(range(len(cells))):
        row = cells[i].start[0]
        if row - scroll + height - 1 < 0:
            break
    # XXX: remove this line when render_cell is fixed
    if cells[i].start[0] - scroll + height <= 0:
        i += 1
    render_from(i, force = True, clear_after = True)

lock = threading.Lock()
def output(s = '', float = False, priority = 10, frozen = False,
            indent = 0, before = None, after = None):
    with lock:
        rel = before or after
        if rel:
            i, _ = find_cell(rel.h)
            is_floating = rel.is_floating
            float = cells[i].float
            if before:
                i -= 1
        elif float and priority:
            is_floating = True
            float = priority
            for i in reversed(range(len(cells))):
                if cells[i].float <= float:
                    break
        else:
            is_floating = False
            i = len(cells) - 1
            while cells[i].float and i > 0:
                i -= 1
        # put('xx %d\n' % i)
        cell = Cell()
        cell.content = parse(s)
        cell.frozen = frozen
        cell.float = float
        cell.indent = indent
        cell.start = cells[i].end
        i += 1
        cells.insert(i, cell)
        h = Handle(cell, is_floating)
        if s == '':
            cell.end = cell.start
            return h
        # the invariant is that the cursor is placed after the last cell
        if i == len(cells) - 1:
            render_cell(cell, clear_after = True)
            flush()
        else:
            render_from(i, clear_after = True)
        return h

def find_cell(h):
    for i, c in enumerate(cells):
        if id(c) == h:
            return i, c
    raise KeyError

def discard_frozen():
    # we assume that no cell will shrink very much and that noone has space
    # for more than MAX_TERM_HEIGHT lines in their terminal
    while len(cells) > 1 and scroll - cells[0].end[0] > MAX_TERM_HEIGHT:
        c = cells.pop(0)
        del c # trigger GC maybe, kthxbai

def update(h, s):
    with lock:
        try:
            i, c = find_cell(h)
        except KeyError:
            return
        if not c.frozen and c.content != s:
            c.content = parse(s)
            render_from(i, clear_after = True)

def freeze(h):
    try:
        i, c = find_cell(h)
        c.frozen = True
        c.float = 0
        if c.content == []:
            cells.pop(i)
        discard_frozen()
    except KeyError:
        return

def delete(h):
    update(h, '')
    freeze(h)
