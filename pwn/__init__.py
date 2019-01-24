# Promote useful stuff to toplevel
from __future__ import absolute_import

from pwn.toplevel import *

pwnlib.args.initialize()
pwnlib.log.install_default_handler()
pwnlib.config.initialize()

log = pwnlib.log.getLogger('pwnlib.exploit')
args = pwnlib.args.args

if not platform.architecture()[0].startswith('64') and sys.version_info() < (3,):
    """Determines if the current Python interpreter is supported by Pwntools.

    See Gallopsled/pwntools#518 for more information."""
    log.warn_once('Pwntools does not support 32-bit Python 2.  Use a 64-bit release or Python 3.')

with context.local(log_console=sys.stderr):
    pwnlib.update.check_automatically()
