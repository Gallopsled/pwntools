"""
When running in term-mode (import `pwn` rather than `pwnlib`, stdout is a TTY
and not running in a REPL), we can do proper indentation where lines too long to
fit on a screen are split into multiple individually indented lines.

Too see the difference try running with::

  $ python indented.py

and

  $ python -i indented.py

Also notice that `pause()` can react on any key when in `term_mode`.
"""

from pwn import *

context.log_level = 'info'

log.indented('A' * 100)
log.indented('B' * 100)
log.indented('C' * 100)

pause()
