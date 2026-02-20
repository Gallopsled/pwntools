"""
Some glibc related convenient functions.
"""
from pwnlib.context import context
from pwnlib.util.fiddling import ror, rol

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
    Perform ``PROTECT_PTR`` in glibc heap macros to protect pointers.
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
    """
    return (word_addr >> 12) ^ value
