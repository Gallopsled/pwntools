import select, sys, string, os, errno
from keyconsts import *

_fd = sys.stdin.fileno()

def _debug (s):
    if DEBUG:
        sys.stderr.write(s + '\n')

def _getch (timeout = 0):
    while True:
        try:
            rfds, _wfds, _xfds = select.select([_fd], [], [], timeout)
            if rfds:
                c = os.read(_fd, 1)
                return ord(c) if c else None
            else:
                return None
        except select.error as e:
            if e.args[0] == errno.EINTR:
                continue
            raise

def getraw (timeout = None):
    '''Get list of raw key codes corresponding to zero or more key presses'''
    cs = []
    c = _getch(timeout)
    while c <> None: # timeout
        cs.append(c)
        if c == None: # EOF
            break
        c = _getch()
    return cs

class Key:
    def __init__ (self, type, code = None, mods = MOD_NONE):
        self.type = type
        self.code = code
        self.mods = mods
        self._str = None

    def __str__ (self):
        if self._str:
            return self._str
        if   self.type == TYPE_UNICODE:
            if self.code == ' ':
                s = '<space>'
            else:
                s = self.code
        elif self.type == TYPE_KEYSYM:
            s = KEY_NAMES.get(self.code, '<SYMNAME-%d>' % self.code)
        elif self.type == TYPE_FUNCTION:
            s = '<f%d>' % self.code
        elif self.type == TYPE_POSITION:
            s = 'Position(%d, %d)' % self.code
        elif self.type == TYPE_EOF:
            s = 'EOF'
        else:
            s = '<UNKNOWN>'
        if self.mods & MOD_SHIFT:
            s = 'S-' + s
        if self.mods & MOD_ALT:
            s = 'M-' + s
        if self.mods & MOD_CTRL:
            s = 'C-' + s
        self._str = s
        return s

    def __repr__ (self):
        return self.__str__()

_cbuf = []
_kbuf = []

def _read (timeout = 0):
    _cbuf.extend(getraw(timeout))

def _peek ():
    if _cbuf:
        return _peek_ti() or _peek_csi() or _peek_simple()

def get (timeout = None):
    if _kbuf:
        return _kbuf.pop(0)
    k = _peek()
    if k:
        return k
    _read(timeout)
    return _peek()

def unget (k):
    _kbuf.append(k)

# terminfo
def _name_to_key (fname):
    if   fname in FUNCSYMS:
        k = Key(TYPE_KEYSYM, *FUNCSYMS[fname])
    elif fname[0] == 'f' and fname[1:].isdigit():
        k = Key(TYPE_FUNCTION, int(fname[1:]))
    elif fname[0] == 's':
        k = _name_to_key(fname[1:])
        if k:
            k.mods |= MOD_SHIFT
    else:
        return None
    return k

import curses
curses.setupterm()
capcache = {}
def cap (c):
    s = capcache.get(c)
    if s:
        return s
    s = curses.tigetstr(c) or ''
    capcache[c] = s
    return s

_ti_table = []
for fname, name in zip(STRFNAMES, STRNAMES):
    seq = cap(name)
    if not seq:
        continue
    k = _name_to_key(fname)
    if k:
        _ti_table.append((map(ord, seq), k))

def _peek_ti ():
    global _cbuf
    # print 'ti', _cbuf, '\r'
    # XXX: Faster lookup, plox
    for seq, key in _ti_table:
        if _cbuf[:len(seq)] == seq:
            _cbuf = _cbuf[len(seq):]
            return key

# csi
def _parse_csi (offset):
    i = offset
    while i < len(_cbuf):
        c = _cbuf[i]
        if c >= 0x40 and c < 0x80:
            break
        i += 1
    if i >= len(_cbuf):
        return
    end = i
    cmd = [c, None, None]

    i = offset
    in_num = False
    args = []
    if _cbuf[i] >= ord('<') and _cbuf[i] <= ord('?'):
        cmd[1] = _cbuf[i]
        i += 1
    while i < end:
        c = _cbuf[i]
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

def _csi_func (cmd, args):
    k = Key(TYPE_UNKNOWN)
    if len(args) > 1 and args[1]:
        k.mods |= args[1] - 1

    if   args[0] == 0x1b and len(args) == 3:
        k.type = TYPE_KEYSYM
        k.code = args[2]
        return k
    elif args[0] in _csi_funcs:
        f = _csi_funcs[args[0]]
        k.type = f[0]
        k.code = f[1]
        return k

def _csi_ss3 (cmd, args):
    t, c = _csi_ss3s[chr(cmd[0])]
    k = Key(t, c)
    if len(args) > 1 and args[1]:
        k.mods |= args[1] - 1
    return k

def _csi_u (cmd, args):
    k = Key(TYPE_UNICODE, args[0])
    if len(args) > 1 and args[1]:
        k.mods |= args[1] - 1
    return k

def _csi_R (cmd, args):
    if cmd[0] == ord('R') and cmd[1] == ord('?'):
        if len(args) < 2:
            return
        return Key(TYPE_POSITION, (args[1], args[0]))
    else:
        return _csi_ss3(cmd, args)

_csi_handlers = {
    '~' : _csi_func,
    'u' : _csi_u,
    'R' : _csi_R,
    }

_csi_ss3s = {
    'A': (TYPE_KEYSYM, KEY_UP),
    'B': (TYPE_KEYSYM, KEY_DOWN),
    'C': (TYPE_KEYSYM, KEY_RIGHT),
    'D': (TYPE_KEYSYM, KEY_LEFT),
    'E': (TYPE_KEYSYM, KEY_BEGIN),
    'F': (TYPE_KEYSYM, KEY_END),
    'H': (TYPE_KEYSYM, KEY_HOME),
    'P': (TYPE_FUNCTION, 1),
    'Q': (TYPE_FUNCTION, 2),
    'R': (TYPE_FUNCTION, 3),
    'S': (TYPE_FUNCTION, 4),
    'Z': (TYPE_KEYSYM, KEY_TAB),
}

_csi_ss3kp = {

}

_csi_funcs = {
    1 : (TYPE_KEYSYM, KEY_FIND),
    2 : (TYPE_KEYSYM, KEY_INSERT),
    3 : (TYPE_KEYSYM, KEY_DELETE),
    4 : (TYPE_KEYSYM, KEY_SELECT),
    5 : (TYPE_KEYSYM, KEY_PAGEUP),
    6 : (TYPE_KEYSYM, KEY_PAGEDOWN),
    7 : (TYPE_KEYSYM, KEY_HOME),
    8 : (TYPE_KEYSYM, KEY_END),
    11: (TYPE_FUNCTION, 1),
    12: (TYPE_FUNCTION, 2),
    13: (TYPE_FUNCTION, 3),
    14: (TYPE_FUNCTION, 4),
    15: (TYPE_FUNCTION, 5),
    17: (TYPE_FUNCTION, 6),
    18: (TYPE_FUNCTION, 7),
    19: (TYPE_FUNCTION, 8),
    20: (TYPE_FUNCTION, 9),
    21: (TYPE_FUNCTION, 10),
    23: (TYPE_FUNCTION, 11),
    24: (TYPE_FUNCTION, 12),
    25: (TYPE_FUNCTION, 13),
    26: (TYPE_FUNCTION, 14),
    28: (TYPE_FUNCTION, 15),
    29: (TYPE_FUNCTION, 16),
    31: (TYPE_FUNCTION, 17),
    32: (TYPE_FUNCTION, 18),
    33: (TYPE_FUNCTION, 19),
    34: (TYPE_FUNCTION, 20),
    }

def _peekkey_csi (offset):
    global _cbuf
    ret = _parse_csi(offset)
    if not ret:
        _cbuf = _cbuf[offset:]
        return Key(TYPE_UNICODE, '[', MOD_ALT)
    cmd, args, numb = ret
    # print cmd, args, '\r'
    _cbuf = _cbuf[numb:]
    k = None
    if   chr(cmd[0]) in _csi_handlers:
        k = _csi_handlers[chr(cmd[0])](cmd, args)
    elif chr(cmd[0]) in _csi_ss3s:
        k = _csi_ss3(cmd, args)
        if k and chr(cmd[0]) == 'Z':
            k.mods |= MOD_SHIFT

    if k:
        return k
    else:
        return Key(TYPE_UNKNOWN_CSI, (cmd, args))

def _peekkey_ss3 (offset):
    global _cbuf
    if len(_cbuf) <= offset:
        return Key(TYPE_UNICODE, 'O', MOD_ALT)
    cmd = _cbuf[offset]
    if cmd < 0x40 or cmd >= 0x80:
        return
    _cbuf = _cbuf[numb:]

    if chr(cmd) in _csi_ss3s:
        return Key(*_csi_ss3s[chr(cmd)])

    if chr(cmd) in _csi_ss3kp:
        t, c, a = _csi_ss3kp[chr(cmd)]
        if CONVERTKP and a:
            return Key(TYPE_UNICODE, a)
        else:
            return Key(t, c)

def _peek_csi ():
    global _cbuf
    # print 'csi', _cbuf, '\r'
    c0 = _cbuf[0]
    if   c0 == 0x1b and len(_cbuf) >= 2:
        c1 = _cbuf[1]
        if   c1 == ord('['):
            return _peekkey_csi(2)
        elif c1 == ord('O'):
            return _peekkey_ss3(2)
    elif c0 == 0x8f:
        return _peekkey_ss3(1)
    elif c0 == 0x9b:
        return _peekkey_csi(1)

def _peek_simple ():
    global _cbuf
    # print 'simple', _cbuf, '\r'
    if not _cbuf:
        return
    c0 = _cbuf.pop(0)
    if   c0 is None:
        _cbuf = []
        return Key(TYPE_EOF)
    elif c0 == 0x1b:
        if _cbuf:
            k = _peek()
            # print k
            if k:
                # need to deep copy or we risk modifying keys in ti table
                return Key(k.type, k.code, k.mods | MOD_ALT)
        else:
            return Key(TYPE_KEYSYM, KEY_ESCAPE)
    elif c0 < 0xa0:
        if   c0 < 0x20:
            if   c0 == 8:
                k = Key(TYPE_KEYSYM, KEY_BACKSPACE)
            elif c0 == 9:
                k = Key(TYPE_KEYSYM, KEY_TAB)
            elif c0 == 13:
                k = Key(TYPE_KEYSYM, KEY_ENTER)
            else:
                k = Key(TYPE_UNICODE)
                if   c0 == 0:
                    k.code = ' '
                elif chr(c0 + 0x40) in string.uppercase:
                    k.code = chr(c0 + 0x60)
                else:
                    k.code = chr(c0 + 0x40)
                k.mods |= MOD_CTRL
        elif c0 == 0x7f:
            # print 'del\r'
            k = Key(TYPE_KEYSYM, KEY_DEL)
        elif c0 >= 0x20 and c0 < 0x80:
            k = Key(TYPE_UNICODE, chr(c0))
        else:
            k = Key(TYPE_UNICODE, chr(c0 - 0x40), MOD_CTRL | MOD_ALT)
    else: # utf8
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
            c = [c0] + _cbuf[:n - 1]
            k = Key(TYPE_UNICODE, ''.join(chr(b) for b in c))
            _cbuf = _cbuf[n - 1:]
        else:
            k = Key(TYPE_UNKNOWN, _cbuf)
            _cbuf = []
    return k
