__all__ = ['get']
import sys
if sys.platform == 'win32':
    from pwnlib.term.windows_termcap import get
else:
    from pwnlib.term.unix_termcap import get

