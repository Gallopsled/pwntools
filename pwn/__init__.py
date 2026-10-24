# Promote useful stuff to toplevel
from pwn.toplevel import *
import pwnlib.update

pwnlib.args.initialize()
pwnlib.log.install_default_handler()
pwnlib.config.initialize()

# Replace the module with the actual args object so that `from pwn import args` works as expected.
args = pwnlib.args.args  # type: ignore[assignment]

if not platform.architecture()[0].startswith('64'):
    """Determines if the current Python interpreter is supported by Pwntools.

    See Gallopsled/pwntools#518 for more information."""
    log.warn_once('Pwntools does not support 32-bit Python.  Use a 64-bit release.')

with context.local(log_console=sys.stderr):
    pwnlib.update.check_automatically()
