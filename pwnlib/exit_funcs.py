from pwnlib.util.fiddling import rol
from pwnlib.util.packing import *

__all__ = ["encode_ptr", "CxaFunc", "AtFunc", "OnFunc"]


def encode_ptr(ptr, ptr_guard, width=Nonte):
    """
    Encodes a function pointer using glibc's pointer-mangling scheme.
    """
    if width is None:
        width = context.bits

    if width == 64:
        return rol(ptr ^ ptr_guard, 0x11, 64) & ((1 << 64) - 1)
    elif width == 32:
        return rol(ptr ^ ptr_guard, 0x9, 32) & ((1 << 32) - 1)
    else:
        raise ValueError(f"Unsupported architecture for pointer encoding: {context.arch}")


class CxaFunc:
    def __init__(self, fp, arg, width=None):
        self.fp = fp
        self.arg = arg
        self.width = width

    def encode(ptr_guard) -> bytes:
        # ef_cxa == 4 | encoded function pointer | argument | dso handle set to NULL
        return flat(4, encode_ptr(self.fp, ptr_guard, self.width), self.arg, 0)


class AtFunc:
    def __init__(self, fp, width=None):
        self.fp = fp
        self.width = width

    def encode(ptr_guard) -> bytes:
        # ef_at == 3 | encoded function pointer
        return flat(3, encode_ptr(self.fp, ptr_guard, self.width))


class OnFunc:
    def __init__(self, fp, arg, width=None):
        self.fp = fp
        self.arg = arg
        self.width = width

    def encode(ptr_guard) -> bytes:
        # ef_at == 2 | encoded function pointer | argument
        return flat(2, encode_ptr(self.fp, ptr_guard, self.width), self.arg)
