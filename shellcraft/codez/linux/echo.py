from core import *
import sys

def main(str, out = 'STD_OUT', loader = ''):
    """Args: str, [out], [loader]
    Writes <str> to <out> (default: STD_OUT).  Reads from STD_IN if <str> is 'STDIN'."""
    if str == 'STDIN':
        str = sys.stdin.read()
    str = repr(str)[1:-1]
    return \
        asm(loader) + \
        template('linux/echo.asm', {'str': str, 'out': out})
