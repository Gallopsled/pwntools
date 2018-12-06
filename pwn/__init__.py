# Promote useful stuff to toplevel
from __future__ import absolute_import

from pwn.toplevel import *

pwnlib.args.initialize()
pwnlib.log.install_default_handler()
pwnlib.config.initialize()

log = pwnlib.log.getLogger('pwnlib.exploit')
args = pwnlib.args.args

if not platform.architecture()[0].startswith('64'):
    """Determines if the current Python interpreter is supported by Pwntools.

    See Gallopsled/pwntools#518 for more information."""
    log.warn_once('Pwntools does not support 32-bit Python.  Use a 64-bit release.')

with context.local(log_console=sys.stderr):
    pwnlib.update.check_automatically()

try:
    raise Exception("wat")
except:
    pass

_f = sys.exc_traceback.tb_frame.f_back
_l = _f.f_lasti
_c = _f.f_code

if 0 <= _l-3 <= _l+6 <= len(_c.co_code):
    _s = _c.co_code[_l-3:_l+6]

    if _s[0] == 'd' and _s[3] == 'l' and _s[6] == 'm':
        _c1 = u16(_s[1:3], endian = 'little')
        _c2 = u16(_s[4:6], endian = 'little')
        _c3 = u16(_s[7:9], endian = 'little')

        if _c.co_consts[_c1] == ('stjerne',) and _c.co_names[_c2] == 'pwn' and _c.co_names[_c3] == 'stjerne':
            stjerne = __import__("pwn")

            for _k, _v in stjerne.__dict__.items():
                if _k.startswith('_'):
                    continue
                _f.f_globals[_k] = _v
