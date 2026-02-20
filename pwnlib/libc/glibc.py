"""
Some glibc related convenient functions.
"""
from __future__ import annotations
from enum import IntEnum

from pwnlib.context import context
from pwnlib.util.fiddling import ror, rol
from pwnlib.util.packing import flat, unpack, unpack_many, _need_bytes

def ptr_mangle(guard: int, value: int) -> int:
    """
    Perform ``PTR_MANGLE`` in glibc to protect pointers.

    Arguments:
        guard(int): The value of ``POINTER_GUARD``.
        value(int): The value to protect.

    Returns:
        Mangled value.

    Examples:
        >>> with context.local(arch='amd64'):
        ...     val = glibc.ptr_mangle(0x1f1f1f1f1f1f1f1f, 0x7f0000000000)
        ...     print(hex(val))
        0xc03e3e3e3e3e3e3e
        >>> with context.local(arch='arm'):
        ...     val = glibc.ptr_mangle(0x1f1f, 0x2e2e0000)
        ...     print(hex(val))
        0x2e2e1f1f
    """
    if context.arch == 'amd64' or context.arch == 'i386':
        return rol(value ^ guard, context.bytes * 2 + 1)
    return value ^ guard

def ptr_demangle(guard: int, mangled: int) -> int:
    """
    Perform ``PTR_DEMANGLE`` in glibc to demangle protected pointer.

    Arguments:
        guard(int): The value of ``POINTER_GUARD``.
        mangled(int): The value to demangle.

    Returns:
        Demangled value.

    Examples:
        >>> with context.local(arch='amd64'):
        ...     val = glibc.ptr_demangle(0x1f1f1f1f1f1f1f1f, 0xc03e3e3e3e3e3e3e)
        ...     print(hex(val))
        0x7f0000000000
        >>> with context.local(arch='aarch64'):
        ...     val = glibc.ptr_demangle(0x1f1f1f1f, 0x2e2e2e2e00000000)
        ...     print(hex(val))
        0x2e2e2e2e1f1f1f1f
    """
    if context.arch == 'amd64' or context.arch == 'i386':
        return ror(mangled, context.bytes * 2 + 1) ^ guard
    return mangled ^ guard

def protect_ptr(word_addr: int, value: int) -> int:
    """
    Perform ` ``PROTECT_PTR`` <https://elixir.bootlin.com/glibc/glibc-2.42/source/malloc/malloc.c#L331>`__ 
    in glibc heap macros to protect pointers.
    ``REVEAL_PTR`` is basically ``PROTECT_PTR``, and since we don't know
    the address of the word, so use ``protect_ptr`` instead.

    Arguments:
        word_addr(int): The address of where ``value`` is stored.
        value(int): The value to protect/reveal

    Returns:
        Protected/Revealed value

    Examples:
        >>> hex(glibc.protect_ptr(0x5e5555556700, 0))
        '0x5e5555556'
        >>> ptr_addr = 0x555555559200
        >>> ptr_value = 0x7ffff7f96058
        >>> glibc.protect_ptr(ptr_addr, glibc.protect_ptr(ptr_addr, ptr_value)) == ptr_value
        True
    """
    return (word_addr >> 12) ^ value

def reveal_ptr_same_page(ptr_value: int) -> int:
    """
    Reveal a pointer that was mangled by protect_ptr without knowing where the pointer is stored.
    Only works if the leaked pointer itself is stored on the same page as its value.

    Arguments:
        ptr_value(int): The mangled pointer.

    Returns:
        int: The original pointer.
    
    Example:

        >>> context.clear(arch='amd64')
        >>> ptr_addr = 0x555555559200
        >>> ptr_value = 0x555555559380
        >>> glibc.reveal_ptr_same_page(glibc.protect_ptr(ptr_addr, ptr_value)) == ptr_value
        True
        >>> ptr_addr = 0x555555559200
        >>> ptr_value = 0x55555556a380
        >>> glibc.reveal_ptr_same_page(glibc.protect_ptr(ptr_addr, ptr_value)) == ptr_value
        False
    """
    mask = 0xfff << (context.bits - 12)
    while mask:
        key = ptr_value & mask
        ptr_value ^= key >> 12
        mask >>= 12
    return ptr_value


class ExitFlavor(IntEnum):
    FREE = 0
    USED = 1
    ON   = 2
    AT   = 3
    CXA  = 4

class ExitFunc:
    flavor: ExitFlavor
    fn: int
    guard: int
    arg: int
    dso: int

    def __init__(self, flavor: ExitFlavor, func: int, guard: int,
                 arg: int | None = None, dso: int | None = None):
        self.flavor = flavor
        self.fn = func
        self.guard = guard
        self.arg = arg
        self.dso = dso

        match flavor:
            case ExitFlavor.ON:
                if arg is None:
                    raise TypeError(f'on_exit requires an arg pointer')
            case ExitFlavor.FREE | ExitFlavor.USED | ExitFlavor.AT:
                pass
            case ExitFlavor.CXA:
                if arg is None or dso is None:
                    raise TypeError(f'cxa_exit requires both arg and dso_handle pointer')
            case _:
                raise TypeError(f'flavor must be an ExitFlavor, instead of {type(flavor)}')

    def __repr__(self) -> str:
        match self.flavor:
            case ExitFlavor.ON:
                extra = f', arg={self.arg:#x}'
            case ExitFlavor.AT:
                extra = ''
            case ExitFlavor.CXA:
                extra = f', arg={self.arg:#x}, dso_handle={self.dso:#x}'
            case ExitFlavor.USED | ExitFlavor.FREE:
                return f'ExitFunc({self.flavor.name})'

        return f'ExitFunc({self.flavor.name}, fn={self.fn:#x} ^ {self.guard:#x}{extra})'

    def __bytes__(self) -> bytes:
        match self.flavor:
            case ExitFlavor.ON:
                return flat(self.flavor, ptr_mangle(self.guard, self.fn),
                            self.arg)
            case ExitFlavor.AT:
                return flat(self.flavor, ptr_mangle(self.guard, self.fn))
            case ExitFlavor.CXA:
                return flat(self.flavor, ptr_mangle(self.guard, self.fn),
                            self.arg, self.dso)
            case ExitFlavor.FREE | ExitFlavor.USED:
                return flat(self.flavor)

    def __flat__(self) -> bytes:
        return bytes(self)

    @staticmethod
    def from_bytes(data: bytes, guard: int) -> ExitFunc:
        """
        Examples:
            >>> context.arch = 'amd64'
            >>> guard = 0x2f21c4a298024bcd
            >>> blob = bytes.fromhex('0300000000000000435ea835ae9aef23')
            >>> glibc.ExitFunc.from_bytes(blob, guard)
            ExitFunc(AT, fn=0x555555555119 ^ 0x2f21c4a298024bcd)
            >>> blob = bytes.fromhex('0200000000000000435ea835ae9aef230000371337130000')
            >>> glibc.ExitFunc.from_bytes(blob, guard)
            ExitFunc(ON, fn=0x555555555119 ^ 0x2f21c4a298024bcd, arg=0x133713370000)
            >>> blob = bytes.fromhex('0000000000000000')
            >>> glibc.ExitFunc.from_bytes(blob, guard)
            ExitFunc(FREE)
            >>> blob = bytes.fromhex('0100000000000000')
            >>> glibc.ExitFunc.from_bytes(blob, guard)
            ExitFunc(USED)
        """
        data = _need_bytes(data)
        if len(data) % 4 != 0 or len(data) == 0:
            raise ValueError(f'data must be aligned to word boundry ({context.bytes} bytes)')
        words = unpack_many(data)
        try:
            flavor = ExitFlavor(words[0])
            match flavor:
                case ExitFlavor.FREE | ExitFlavor.USED:
                    return ExitFunc(flavor, 0, guard)
                case ExitFlavor.ON:
                    return ExitFunc(flavor, ptr_demangle(guard, words[1]), guard,
                                    words[2])
                case ExitFlavor.AT:
                    return ExitFunc(flavor, ptr_demangle(guard, words[1]), guard)
                case ExitFlavor.CXA:
                    return ExitFunc(flavor, ptr_demangle(guard, words[1]), guard,
                                    words[2], words[3])
        except IndexError:
            raise ValueError(f'Insufficient data when decoding ExitFunc') from None


class ExitFuncList:
    next: int
    idx: int
    fns: list[ExitFunc]

    def __init__(self, nextp: int, funcs: list[ExitFunc]):
        self.nextp = nextp
        self.fns = funcs
        self.idx = len(funcs)

    def __repr__(self) -> str:
        return f'ExitFuncList(next={self.nextp:#x}, idx={self.idx}, fns={self.fns})'

    def __bytes__(self) -> bytes:
        return flat(self.nextp, self.idx, self.fns)

    def __flat__(self) -> bytes:
        return bytes(self)

    @staticmethod
    def from_bytes(data: bytes, guard: int) -> ExitFuncList:
        """
        Examples:
            >>> context.arch = 'amd64'
            >>> guard = 0x2d42599562d398bb
            >>> blob = bytes.fromhex('000000000000000001000000000000000400000000000000845ab66f5e2ad54c00000000000000000000000000000000')
            >>> glibc.ExitFuncList.from_bytes(blob, guard)
            ExitFuncList(next=0x0, idx=1, fns=[ExitFunc(CXA, fn=0x7ffff7fcaf60 ^ 0x2d42599562d398bb, arg=0x0, dso_handle=0x0)])
        """
        data = _need_bytes(data)
        try:
            nextp = unpack(data[0:context.bytes])
            size  = unpack(data[context.bytes:context.bytes * 2])
            off = context.bytes * 2
            func_sz = 4 * context.bytes
            fns = [ExitFunc.from_bytes(data[off + i * func_sz:off + (i + 1) * func_sz], guard)
                   for i in range(size)]
            return ExitFuncList(nextp, fns)
        except IndexError:
            raise ValueError(f'Insufficient data when decoding ExitFuncList') from None
