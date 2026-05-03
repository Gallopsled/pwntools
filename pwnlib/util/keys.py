r"""
Constants and helpers for terminal control characters and ANSI escape
sequences, intended to make calls like :meth:`.tube.send` self-documenting
instead of relying on opaque byte literals such as ``b'\x03'``.

Example:

    >>> from pwnlib.util.keys import CTRL_C, ENTER, UP
    >>> CTRL_C
    b'\x03'
    >>> ENTER
    b'\r'
    >>> UP
    b'\x1b[A'
    >>> ctrl('a')
    b'\x01'
    >>> ctrl('Z')
    b'\x1a'
    >>> alt('x')
    b'\x1bx'
    >>> csi('H')
    b'\x1b[H'
    >>> csi('5A')
    b'\x1b[5A'
"""

__all__ = [
    # Generators
    'ctrl', 'alt', 'csi',
    # C0 controls (named)
    'NUL', 'SOH', 'STX', 'ETX', 'EOT', 'ENQ', 'ACK', 'BEL',
    'BS', 'TAB', 'LF', 'VT', 'FF', 'CR', 'SO', 'SI',
    'DLE', 'DC1', 'DC2', 'DC3', 'DC4', 'NAK', 'SYN', 'ETB',
    'CAN', 'EM', 'SUB', 'ESC', 'FS', 'GS', 'RS', 'US',
    'DEL',
    # Common aliases
    'BACKSPACE', 'ENTER', 'NEWLINE', 'TAB_KEY', 'ESCAPE', 'SPACE',
    # Ctrl+letter aliases (most common in shell interaction)
    'CTRL_A', 'CTRL_B', 'CTRL_C', 'CTRL_D', 'CTRL_E', 'CTRL_F',
    'CTRL_G', 'CTRL_H', 'CTRL_I', 'CTRL_J', 'CTRL_K', 'CTRL_L',
    'CTRL_M', 'CTRL_N', 'CTRL_O', 'CTRL_P', 'CTRL_Q', 'CTRL_R',
    'CTRL_S', 'CTRL_T', 'CTRL_U', 'CTRL_V', 'CTRL_W', 'CTRL_X',
    'CTRL_Y', 'CTRL_Z',
    'CTRL_BACKSLASH', 'CTRL_RBRACKET', 'CTRL_CARET', 'CTRL_UNDERSCORE',
    # Arrow keys
    'UP', 'DOWN', 'RIGHT', 'LEFT',
    # Navigation
    'HOME', 'END', 'PAGE_UP', 'PAGE_DOWN', 'INSERT', 'DELETE',
    # Function keys
    'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
    # Useful CSI sequences for screen control
    'CLEAR_SCREEN', 'CLEAR_LINE',
]


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------


def ctrl(char):
    r"""ctrl(char) -> bytes

    Return the C0 control byte for a Ctrl+\ *char* keypress.

    *char* must be a single ASCII letter (``a``–``z``, ``A``–``Z``) or one of
    ``@``, ``[``, ``\``, ``]``, ``^``, ``_``, ``?`` (the symbolic Ctrl
    targets).  Letter case is ignored.

    Example:

        >>> ctrl('a')
        b'\x01'
        >>> ctrl('C')
        b'\x03'
        >>> ctrl('[')
        b'\x1b'
        >>> ctrl('?')
        b'\x7f'
    """
    if not isinstance(char, str) or len(char) != 1:
        raise ValueError("ctrl(): char must be a single-character string")
    code = ord(char.upper())
    if 0x40 <= code <= 0x5f:
        return bytes((code & 0x1f,))
    if char == '?':
        # Ctrl-? is conventionally DEL (0x7f)
        return b'\x7f'
    raise ValueError("ctrl(): %r has no Ctrl-form (use a letter or @[\\]^_?)" % char)


def alt(char):
    r"""alt(char) -> bytes

    Return the bytes that most terminals emit for an Alt/Meta+\ *char*
    keypress: an ``ESC`` prefix followed by *char*.

    *char* may be a single-character ``str`` or any ``bytes``-like value, in
    which case the returned bytes are ``b'\x1b' + bytes(char)``.

    Example:

        >>> alt('x')
        b'\x1bx'
        >>> alt(b'.')
        b'\x1b.'
        >>> alt('\r')
        b'\x1b\r'
    """
    if isinstance(char, str):
        char = char.encode('latin-1')
    elif isinstance(char, (bytes, bytearray, memoryview)):
        char = bytes(char)
    else:
        raise TypeError("alt(): char must be str or bytes-like")
    return b'\x1b' + char


def csi(rest):
    r"""csi(rest) -> bytes

    Build a CSI (Control Sequence Introducer) escape, i.e. ``ESC [`` followed
    by *rest*.

    *rest* may be a ``str`` (encoded as latin-1) or any ``bytes``-like value.

    Example:

        >>> csi('H')
        b'\x1b[H'
        >>> csi('2J')
        b'\x1b[2J'
        >>> csi(b'5;10H')
        b'\x1b[5;10H'
    """
    if isinstance(rest, str):
        rest = rest.encode('latin-1')
    elif isinstance(rest, (bytes, bytearray, memoryview)):
        rest = bytes(rest)
    else:
        raise TypeError("csi(): rest must be str or bytes-like")
    return b'\x1b[' + rest


# ---------------------------------------------------------------------------
# C0 control characters (0x00–0x1f) plus DEL.
# ---------------------------------------------------------------------------

NUL = b'\x00'  #: Null
SOH = b'\x01'  #: Start of heading (Ctrl-A)
STX = b'\x02'  #: Start of text (Ctrl-B)
ETX = b'\x03'  #: End of text (Ctrl-C)
EOT = b'\x04'  #: End of transmission (Ctrl-D)
ENQ = b'\x05'  #: Enquiry (Ctrl-E)
ACK = b'\x06'  #: Acknowledge (Ctrl-F)
BEL = b'\x07'  #: Bell (Ctrl-G)
BS  = b'\x08'  #: Backspace (Ctrl-H)
TAB = b'\x09'  #: Horizontal tab (Ctrl-I)
LF  = b'\x0a'  #: Line feed (Ctrl-J)
VT  = b'\x0b'  #: Vertical tab (Ctrl-K)
FF  = b'\x0c'  #: Form feed (Ctrl-L)
CR  = b'\x0d'  #: Carriage return (Ctrl-M)
SO  = b'\x0e'  #: Shift out (Ctrl-N)
SI  = b'\x0f'  #: Shift in (Ctrl-O)
DLE = b'\x10'  #: Data link escape (Ctrl-P)
DC1 = b'\x11'  #: Device control 1 (Ctrl-Q, XON)
DC2 = b'\x12'  #: Device control 2 (Ctrl-R)
DC3 = b'\x13'  #: Device control 3 (Ctrl-S, XOFF)
DC4 = b'\x14'  #: Device control 4 (Ctrl-T)
NAK = b'\x15'  #: Negative acknowledge (Ctrl-U)
SYN = b'\x16'  #: Synchronous idle (Ctrl-V)
ETB = b'\x17'  #: End of transmission block (Ctrl-W)
CAN = b'\x18'  #: Cancel (Ctrl-X)
EM  = b'\x19'  #: End of medium (Ctrl-Y)
SUB = b'\x1a'  #: Substitute (Ctrl-Z)
ESC = b'\x1b'  #: Escape
FS  = b'\x1c'  #: File separator (Ctrl-\\)
GS  = b'\x1d'  #: Group separator (Ctrl-])
RS  = b'\x1e'  #: Record separator (Ctrl-^)
US  = b'\x1f'  #: Unit separator (Ctrl-_)
DEL = b'\x7f'  #: Delete

# Friendly aliases for the most common keys
BACKSPACE = BS
ENTER     = CR
NEWLINE   = LF
TAB_KEY   = TAB
ESCAPE    = ESC
SPACE     = b' '

# Ctrl-letter aliases (kept verbose for readability at the call site)
CTRL_A = SOH
CTRL_B = STX
CTRL_C = ETX
CTRL_D = EOT
CTRL_E = ENQ
CTRL_F = ACK
CTRL_G = BEL
CTRL_H = BS
CTRL_I = TAB
CTRL_J = LF
CTRL_K = VT
CTRL_L = FF
CTRL_M = CR
CTRL_N = SO
CTRL_O = SI
CTRL_P = DLE
CTRL_Q = DC1
CTRL_R = DC2
CTRL_S = DC3
CTRL_T = DC4
CTRL_U = NAK
CTRL_V = SYN
CTRL_W = ETB
CTRL_X = CAN
CTRL_Y = EM
CTRL_Z = SUB
CTRL_BACKSLASH  = FS
CTRL_RBRACKET   = GS
CTRL_CARET      = RS
CTRL_UNDERSCORE = US


# ---------------------------------------------------------------------------
# Common ANSI / xterm sequences accepted on the wire by typical line editors
# (readline, bash, zsh, etc.).
# ---------------------------------------------------------------------------

UP        = b'\x1b[A'
DOWN      = b'\x1b[B'
RIGHT     = b'\x1b[C'
LEFT      = b'\x1b[D'
HOME      = b'\x1b[H'
END       = b'\x1b[F'
INSERT    = b'\x1b[2~'
DELETE    = b'\x1b[3~'
PAGE_UP   = b'\x1b[5~'
PAGE_DOWN = b'\x1b[6~'

# Function keys (xterm sequences)
F1  = b'\x1bOP'
F2  = b'\x1bOQ'
F3  = b'\x1bOR'
F4  = b'\x1bOS'
F5  = b'\x1b[15~'
F6  = b'\x1b[17~'
F7  = b'\x1b[18~'
F8  = b'\x1b[19~'
F9  = b'\x1b[20~'
F10 = b'\x1b[21~'
F11 = b'\x1b[23~'
F12 = b'\x1b[24~'

# Screen control
CLEAR_SCREEN = b'\x1b[2J'
CLEAR_LINE   = b'\x1b[2K'
