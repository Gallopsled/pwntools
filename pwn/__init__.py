# Promote useful stuff to toplevel
from .toplevel import *

pwnlib.args.initialize()
pwnlib.log.install_default_handler()

log = pwnlib.log.getLogger('pwnlib.exploit')
args = pwnlib.args.args
