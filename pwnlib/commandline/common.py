from pwn import *

choices = map(str, [16,32,64])
choices += list(context.oses)
choices += list(context.architectures)
choices += list(context.endiannesses)

def context_arg(arg):
    try: context.arch = arg
    except: pass
    try: context.os = arg
    except: pass
    try: context.bits = int(arg)
    except: arg
    try: context.endian = arg
    except: pass
    return arg