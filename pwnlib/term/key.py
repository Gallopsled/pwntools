from __future__ import absolute_import

import errno
import os
import select
import string
import sys

from pwnlib.term import keyconsts as kc
from pwnlib.term import termcap

__all__ = ['getch', 'getraw', 'get', 'unget']

# When set, convert keypad codes into regular key presses, e.g. "+" instead of
# `<kp plus>`
FLAG_CONVERTKP = True

try:    _fd = sys.stdin.fileno()
except Exception: _fd = file('/dev/null', 'r').fileno()

def getch(timeout = 0):
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

def getraw(timeout = None):
    '''Get list of raw key codes corresponding to zero or more key presses'''
    cs = []
    c = getch(timeout)
    while c != None: # timeout
        cs.append(c)
        if c == None: # EOF
            break
        c = getch()
    return cs

class Matcher:
    def __init__(self, desc):
        self._desc = desc
        desc = desc.split('-')
        mods = desc[:-1]
        k = desc[-1]
        if k == '<space>':
            k = ' '
        m = kc.MOD_NONE
        if 'S' in mods:
            m |= kc.MOD_SHIFT
        if 'M' in mods:
            m |= kc.MOD_ALT
        if 'C' in mods:
            m |= kc.MOD_CTRL
        if   len(k) == 1:
            t = kc.TYPE_UNICODE
            c = k
            h = ord(k)
        elif k[0] == '<' and k in kc.KEY_NAMES_REVERSE:
            t = kc.TYPE_KEYSYM
            c = kc.KEY_NAMES_REVERSE[k]
            h = c
        elif k[:2] == '<f' and k[-1] == '>' and k[2:-1].isdigit():
            t = kc.TYPE_FUNCTION
            c = int(k[2:-1])
            h = c
        else:
            raise ValueError('bad key description "%s"' % k)
        self._type = t
        self._code = c
        self._mods = m
        self._hash = h | (m << 6) | (t << 7)

    def __call__(self, k):
        if isinstance(k, Key):
            return all([k.type == self._type,
                        k.code == self._code,
                        k.mods == self._mods,
                        ])

    def __eq__(self, other):
        if   isinstance(other, Matcher):
            return all([other._type == self._type,
                        other._code == self._code,
                        other._mods == self._mods,
                        ])
        elif isinstance(other, Key):
            return self.__call__(other)
        else:
            return False

    def __neq__(self, other):
        return not self == other

    def __hash__(self):
        return self._hash

    def __str__(self):
        return self._desc

class Key:
    def __init__(self, type, code = None, mods = kc.MOD_NONE):
        self.type = type
        self.code = code
        self.mods = mods
        self._str = None

    def __str__(self):
        if self._str:
            return self._str
        if   self.type == kc.TYPE_UNICODE:
            if self.code == ' ':
                s = '<space>'
            else:
                s = self.code
        elif self.type == kc.TYPE_KEYSYM:
            s = kc.KEY_NAMES.get(self.code, '<SYMNAME-%d>' % self.code)
        elif self.type == kc.TYPE_FUNCTION:
            s = '<f%d>' % self.code
        elif self.type == kc.TYPE_POSITION:
            s = 'Position(%d, %d)' % self.code
        elif self.type == kc.TYPE_EOF:
            s = 'EOF'
        else:
            s = '<UNKNOWN>'
        if self.mods & kc.MOD_SHIFT:
            s = 'S-' + s
        if self.mods & kc.MOD_ALT:
            s = 'M-' + s
        if self.mods & kc.MOD_CTRL:
            s = 'C-' + s
        self._str = s
        return s

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        if   isinstance(other, (unicode, str)):
            return Matcher(other)(self)
        elif isinstance(other, Matcher):
            return other(self)
        elif isinstance(other, Key):
            return all([self.type == other.type,
                        self.code == other.code,
                        self.mods == other.mods,
                        ])
        else:
            return False

_cbuf = []
_kbuf = []

def _read(timeout = 0):
    _cbuf.extend(getraw(timeout))

def _peek():
    if _cbuf:
        return _peek_ti() or _peek_csi() or _peek_simple()

def get(timeout = None):
    if _kbuf:
        return _kbuf.pop(0)
    k = _peek()
    if k:
        return k
    _read(timeout)
    return _peek()

def unget(k):
    _kbuf.append(k)

# terminfo
def _name_to_key(fname):
    if   fname in kc.FUNCSYMS:
        k = Key(kc.TYPE_KEYSYM, *kc.FUNCSYMS[fname])
    elif fname[0] == 'f' and fname[1:].isdigit():
        k = Key(kc.TYPE_FUNCTION, int(fname[1:]))
    elif fname[0] == 's':
        k = _name_to_key(fname[1:])
        if k:
            k.mods |= kc.MOD_SHIFT
    else:
        return None
    return k

_ti_table = None

def _peek_ti():
    global _cbuf
    if _ti_table == None:
        _init_ti_table()
    # XXX: Faster lookup, plox
    for seq, key in _ti_table:
        if _cbuf[:len(seq)] == seq:
            _cbuf = _cbuf[len(seq):]
            return key

def _init_ti_table():
    global _ti_table
    _ti_table = []
    for fname, name in zip(kc.STRFNAMES, kc.STRNAMES):
        seq = termcap.get(name)
        if not seq:
            continue
        k = _name_to_key(fname)
        if k:
            _ti_table.append((map(ord, seq), k))

# csi
def _parse_csi(offset):
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

def _csi_func(cmd, args):
    k = Key(kc.TYPE_UNKNOWN)
    if len(args) > 1 and args[1]:
        k.mods |= args[1] - 1

    if   args[0] == 0x1b and len(args) == 3:
        k.type = kc.TYPE_KEYSYM
        k.code = args[2]
        return k
    elif args[0] in _csi_funcs:
        f = _csi_funcs[args[0]]
        k.type = f[0]
        k.code = f[1]
        return k

def _csi_ss3(cmd, args):
    t, c = _csi_ss3s[chr(cmd[0])]
    k = Key(t, c)
    if len(args) > 1 and args[1]:
        k.mods |= args[1] - 1
    return k

def _csi_u(cmd, args):
    k = Key(kc.TYPE_UNICODE, unichr(args[0]))
    if len(args) > 1 and args[1]:
        k.mods |= args[1] - 1
    return k

def _csi_R(cmd, args):
    if cmd[0] == ord('R') and cmd[1] == ord('?'):
        if len(args) < 2:
            return
        return Key(kc.TYPE_POSITION, (args[1], args[0]))
    else:
        return _csi_ss3(cmd, args)

_csi_handlers = {
    '~' : _csi_func,
    'u' : _csi_u,
    'R' : _csi_R,
    }

_csi_ss3s = {
    'A': (kc.TYPE_KEYSYM, kc.KEY_UP),
    'B': (kc.TYPE_KEYSYM, kc.KEY_DOWN),
    'C': (kc.TYPE_KEYSYM, kc.KEY_RIGHT),
    'D': (kc.TYPE_KEYSYM, kc.KEY_LEFT),
    'E': (kc.TYPE_KEYSYM, kc.KEY_BEGIN),
    'F': (kc.TYPE_KEYSYM, kc.KEY_END),
    'H': (kc.TYPE_KEYSYM, kc.KEY_HOME),
    'P': (kc.TYPE_FUNCTION, 1),
    'Q': (kc.TYPE_FUNCTION, 2),
    'R': (kc.TYPE_FUNCTION, 3),
    'S': (kc.TYPE_FUNCTION, 4),
    'Z': (kc.TYPE_KEYSYM, kc.KEY_TAB),
}

_csi_ss3kp = {
    'M': (kc.TYPE_KEYSYM, kc.KEY_KPENTER , None),
    'X': (kc.TYPE_KEYSYM, kc.KEY_KPEQUALS, '='),
    'j': (kc.TYPE_KEYSYM, kc.KEY_KPMULT  , '*'),
    'k': (kc.TYPE_KEYSYM, kc.KEY_KPPLUS  , '+'),
    'l': (kc.TYPE_KEYSYM, kc.KEY_KPCOMMA , ','),
    'm': (kc.TYPE_KEYSYM, kc.KEY_KPMINUS , '-'),
    'n': (kc.TYPE_KEYSYM, kc.KEY_KPPERIOD, '.'),
    'o': (kc.TYPE_KEYSYM, kc.KEY_KPDIV   , '/'),
    'p': (kc.TYPE_KEYSYM, kc.KEY_KP0     , '0'),
    'q': (kc.TYPE_KEYSYM, kc.KEY_KP1     , '1'),
    'r': (kc.TYPE_KEYSYM, kc.KEY_KP2     , '2'),
    's': (kc.TYPE_KEYSYM, kc.KEY_KP3     , '3'),
    't': (kc.TYPE_KEYSYM, kc.KEY_KP4     , '4'),
    'u': (kc.TYPE_KEYSYM, kc.KEY_KP5     , '5'),
    'v': (kc.TYPE_KEYSYM, kc.KEY_KP6     , '6'),
    'w': (kc.TYPE_KEYSYM, kc.KEY_KP7     , '7'),
    'x': (kc.TYPE_KEYSYM, kc.KEY_KP8     , '8'),
    'y': (kc.TYPE_KEYSYM, kc.KEY_KP9     , '9'),
}

_csi_funcs = {
    1 : (kc.TYPE_KEYSYM, kc.KEY_FIND),
    2 : (kc.TYPE_KEYSYM, kc.KEY_INSERT),
    3 : (kc.TYPE_KEYSYM, kc.KEY_DELETE),
    4 : (kc.TYPE_KEYSYM, kc.KEY_SELECT),
    5 : (kc.TYPE_KEYSYM, kc.KEY_PAGEUP),
    6 : (kc.TYPE_KEYSYM, kc.KEY_PAGEDOWN),
    7 : (kc.TYPE_KEYSYM, kc.KEY_HOME),
    8 : (kc.TYPE_KEYSYM, kc.KEY_END),
    11: (kc.TYPE_FUNCTION, 1),
    12: (kc.TYPE_FUNCTION, 2),
    13: (kc.TYPE_FUNCTION, 3),
    14: (kc.TYPE_FUNCTION, 4),
    15: (kc.TYPE_FUNCTION, 5),
    17: (kc.TYPE_FUNCTION, 6),
    18: (kc.TYPE_FUNCTION, 7),
    19: (kc.TYPE_FUNCTION, 8),
    20: (kc.TYPE_FUNCTION, 9),
    21: (kc.TYPE_FUNCTION, 10),
    23: (kc.TYPE_FUNCTION, 11),
    24: (kc.TYPE_FUNCTION, 12),
    25: (kc.TYPE_FUNCTION, 13),
    26: (kc.TYPE_FUNCTION, 14),
    28: (kc.TYPE_FUNCTION, 15),
    29: (kc.TYPE_FUNCTION, 16),
    31: (kc.TYPE_FUNCTION, 17),
    32: (kc.TYPE_FUNCTION, 18),
    33: (kc.TYPE_FUNCTION, 19),
    34: (kc.TYPE_FUNCTION, 20),
    }

def _peekkey_csi(offset):
    global _cbuf
    ret = _parse_csi(offset)
    if not ret:
        _cbuf = _cbuf[offset:]
        return Key(kc.TYPE_UNICODE, u'[', kc.MOD_ALT)
    cmd, args, numb = ret
    # print cmd, args, '\r'
    _cbuf = _cbuf[numb:]
    k = None
    if   chr(cmd[0]) in _csi_handlers:
        k = _csi_handlers[chr(cmd[0])](cmd, args)
    elif chr(cmd[0]) in _csi_ss3s:
        k = _csi_ss3(cmd, args)
        if k and chr(cmd[0]) == 'Z':
            k.mods |= kc.MOD_SHIFT

    if k:
        return k
    else:
        return Key(kc.TYPE_UNKNOWN_CSI, (cmd, args))

def _peekkey_ss3(offset):
    global _cbuf
    if len(_cbuf) <= offset:
        return Key(kc.TYPE_UNICODE, u'O', kc.MOD_ALT)
    cmd = _cbuf[offset]
    if cmd < 0x40 or cmd >= 0x80:
        return
    _cbuf = _cbuf[offset:]

    if chr(cmd) in _csi_ss3s:
        return Key(*_csi_ss3s[chr(cmd)])

    if chr(cmd) in _csi_ss3kp:
        t, c, a = _csi_ss3kp[chr(cmd)]
        if FLAG_CONVERTKP and a:
            return Key(kc.TYPE_UNICODE, a)
        else:
            return Key(t, c)

def _peek_csi():
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

def _peek_simple():
    global _cbuf
    # print 'simple', _cbuf, '\r'
    if not _cbuf:
        return
    c0 = _cbuf.pop(0)
    if   c0 is None:
        _cbuf = []
        return Key(kc.TYPE_EOF)
    elif c0 == 0x1b:
        if _cbuf:
            k = _peek()
            # print k
            if k:
                # need to deep copy or we risk modifying keys in ti table
                return Key(k.type, k.code, k.mods | kc.MOD_ALT)
        else:
            return Key(kc.TYPE_KEYSYM, kc.KEY_ESCAPE)
    elif c0 < 0xa0:
        if   c0 < 0x20:
            if   c0 == 8:
                k = Key(kc.TYPE_KEYSYM, kc.KEY_BACKSPACE)
            elif c0 == 9:
                k = Key(kc.TYPE_KEYSYM, kc.KEY_TAB)
            elif c0 in (10, 13):
                k = Key(kc.TYPE_KEYSYM, kc.KEY_ENTER)
            else:
                k = Key(kc.TYPE_UNICODE)
                if   c0 == 0:
                    k.code = u' '
                elif chr(c0 + 0x40) in string.uppercase:
                    k.code = unichr(c0 + 0x60)
                else:
                    k.code = unichr(c0 + 0x40)
                k.mods |= kc.MOD_CTRL
        elif c0 == 0x7f:
            # print 'del\r'
            k = Key(kc.TYPE_KEYSYM, kc.KEY_DEL)
        elif c0 >= 0x20 and c0 < 0x80:
            k = Key(kc.TYPE_UNICODE, unichr(c0))
        else:
            k = Key(kc.TYPE_UNICODE, unichr(c0 - 0x40), kc.MOD_CTRL | kc.MOD_ALT)
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
            k = Key(kc.TYPE_UNICODE, ''.join(chr(b) for b in c).decode('utf8'))
            _cbuf = _cbuf[n - 1:]
        else:
            k = Key(kc.TYPE_UNKNOWN, _cbuf)
            _cbuf = []
    return k
