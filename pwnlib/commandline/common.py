import sys

import pwnlib
from pwnlib.context import context

pwnlib.log.console.stream = sys.stderr

choices = map(str, [16,32,64])
choices += list(context.oses)
choices += list(context.architectures)
choices += list(context.endiannesses)

def context_arg(arg):
    try: context.arch = arg
    except Exception: pass
    try: context.os = arg
    except Exception: pass
    try: context.bits = int(arg)
    except Exception: arg
    try: context.endian = arg
    except Exception: pass
    return arg
