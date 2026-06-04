r"""
A generic module to construct C data types with pure Python. Downstream data types may
consider combine basic types in ``ctypes`` and ``CArray``, ``CStruct`` and ``CUnion``
in this module to implement basically all C types.

This module provides some features that ``ctypes`` can not:

1. User may access composite variables with ``slice`` to fetch memory.
2. User may set composite members with ``bytes`` object.
3. Easy to layout arch-specific types or layout in packed form. e.g., layout pointer
   for 32-bit types but on 64-bit Python.
4. Directly return ``int`` on basic types.
5. Print composite types in a pwner-friendly form.

Examples:
    >>> from pwnlib.util.c_primitives import *
    >>> from ctypes import *
    >>> from enum import IntEnum, IntFlag
    >>> context.clear(arch='amd64')
    >>> class Token(IntEnum):
    ...     NONE = 0
    ...     READ = 1
    ...     WRITE = 2
    ...
    >>> class Perm(IntFlag):
    ...     R = 1
    ...     W = 2
    ...     X = 4
    ...
    >>> class CToken(CEnum):
    ...     _size_type_ = c_uint
    ...     _disp_type_ = Token
    ...
    >>> class CPerm(CFlag):
    ...     _size_type_ = c_ubyte
    ...     _disp_type_ = Perm
    ...
    >>> class Name(CCharArray):
    ...     _count_ = 8
    ...
    >>> class Raw(CCharArray):
    ...     _count_ = 24
    ...
    >>> class Scores(CArray):
    ...     _type_ = c_ushort
    ...     _count_ = 3
    ...
    >>> Tokens = mk_anonymous_carray(CToken, 2)
    >>> class AutoHeader(CStruct):
    ...     _fields_ = [
    ...         ('tag', c_char),
    ...         ('perm', CPerm),
    ...         ('cursor', c_void_p),
    ...         ('kind', CToken),
    ...         ('name', Name),
    ...     ]
    ...
    >>> class ManualPair(CStruct):
    ...     _fields_ = [
    ...         ('lo', c_ushort, 0, 0),
    ...         ('target', c_void_p, 2, 2),
    ...         ('tail', c_uint, 10, 10),
    ...     ]
    ...
    >>> class Payload(CUnion):
    ...     _fields_ = [
    ...         ('raw', Raw),
    ...         ('scores', Scores),
    ...         ('pair', ManualPair),
    ...     ]
    ...
    >>> class Packet(CStruct):
    ...     _fields_ = [
    ...         ('header', AutoHeader),
    ...         ('payload', Payload),
    ...         ('tokens', Tokens),
    ...         ('perm', CPerm),
    ...         ('handler', c_void_p),
    ...     ]
    ...
    >>> pkt = Packet()
    >>> pkt.payload.pair.offsetof('tail')
    10
    >>> len(pkt.payload)
    24
    >>> len(pkt)
    80
    >>> pkt.header.tag = ord('M')
    >>> pkt.header.perm = Perm.R
    >>> pkt.header.cursor = 0x1122334455667788
    >>> pkt.header.kind = Token.READ + 0xaa00
    >>> pkt.header.name = b'payload!'
    >>> pkt.payload.pair.lo = 0xbeef
    >>> pkt.payload.pair.target = 0x4041424344454647
    >>> pkt.payload.pair.tail = 0x21444150
    >>> pkt.tokens[0] = Token.READ
    >>> pkt.tokens[1] = 0x99
    >>> pkt.perm = Perm.X
    >>> pkt.handler = 0x7f0643fa3f60
    >>> pkt.header[12:20] = b'PWN!\x02'
    >>> pkt[0x30:0x38] = b'/bin/sh'
    >>> pkt
    {
      +0x0  header = {
        +0x0  tag = 0x4d,
        +0x1  perm = 0x1 <Perm.R: 1>,
        +0x8  cursor = 0x214e575055667788,
        +0x10 kind = 0x2 <Token.WRITE: 2>,
        +0x14 name = <70 61 79 6c 6f 61 64 21  |payload!|>,
      },
      +0x20 payload = {
        raw = <
          ef be 47 46 45 44 43 42 41 40 50 41 44 21 00 00  |..GFEDCBA@PAD!..|
          2f 62 69 6e 2f 73 68 00                          |/bin/sh.|
        >,
        scores = [
          0xbeef,
          0x4647,
          0x4445,
        ],
        pair = {
          +0x0 lo = 0xbeef,
          +0x2 target = 0x4041424344454647,
          +0xa tail = 0x21444150,
        },
      },
      +0x38 tokens = [
        0x1 <Token.READ: 1>,
        0x99,
      ],
      +0x40 perm = 0x4 <Perm.X: 4>,
      +0x48 handler = 0x7f0643fa3f60,
    }
    >>> print(pkt)
    {{0x4d, 0x1 <Perm.R>, 0x214e575055667788, 0x2 <Token.WRITE>, <70 61 79 6c 6f 61 64 21>}, {<ef be 47 46 45 44 43 42 41 40 50 41 44 21 00 00 2f 62 69 6e 2f 73 68 00>, [0xbeef, 0x4647, 0x4445], {0xbeef, 0x4041424344454647, 0x21444150}}, [0x1 <Token.READ>, 0x99], 0x4 <Perm.X>, 0x7f0643fa3f60}
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator
from ctypes import (
    _SimpleCData,
    c_char,
    c_char_p,
    c_long,
    c_size_t,
    c_ssize_t,
    c_ulong,
    c_void_p,
    c_wchar_p,
    sizeof,
)
from enum import Enum, Flag, IntEnum, IntFlag
from io import StringIO, TextIOBase
from typing import Any, Generic, TypeAlias, TypeVar, cast, overload

from pwnlib.context import context
from pwnlib.util.packing import _need_bytes, pack, unpack

BaseCType: TypeAlias = type[_SimpleCData]
CompCType: TypeAlias = type['PwnType']
CType: TypeAlias = BaseCType | CompCType
CompCValue: TypeAlias = 'int | PwnType'
BytesLike: TypeAlias = str | bytes | bytearray
ArrayItemT = TypeVar('ArrayItemT', bound='CompCValue')

CTYPE_BASE = cast(BaseCType, c_long.__base__)
VAR_TYPES: list[BaseCType] = [
    c_void_p,
    c_char_p,
    c_wchar_p,
    c_size_t,
    c_ssize_t,
    c_ulong,
    c_long,
]


def _type(o: Any) -> str:
    if isinstance(o, type):
        return o.__name__
    return type(o).__name__


def _separator(s: TextIOBase, v: bool) -> None:
    if v:
        s.write('\n')
    else:
        s.write(' ')


def _verbose_separator(s: TextIOBase, v: bool) -> None:
    if v:
        s.write('\n')


def _remove_non_verbose_tail(s: TextIOBase, v: bool) -> None:
    if not v:
        s.seek(s.tell() - 2)
        s.truncate()


class PwnType:
    """
    The base type of composite C types. DO NOT inherit this class when implementing
    a specific C type. Use specific class down below.

    All variables, including basic C types, are not stored with value directly. Instead,
    the component offset and size is stored, and the actual value is fetched via memory.
    Every composite type stores a ``memoryview`` object on initialization (or create a
    buffer to construct a ``memoryview`` object) so later variables can be read
    directly on memory. In this case, setting underlying memory buffer can affect
    variable value, helping pwners write exploits painlessly.
    """

    _32_size_cache_: int
    _64_size_cache_: int
    _32_align_cache_: int
    _64_align_cache_: int
    _buf: bytearray | None
    _view: memoryview
    _len: int

    def __init__(self, view: memoryview | None) -> None:
        self._len = PwnType._calc_size(self)
        if view is None:
            self._buf = bytearray(self._len)
            self._view = memoryview(self._buf)
        else:
            self._buf = None
            self._view = view

    def _copy_from(self, value: Any) -> type[Any] | None:
        """
        Sets a variable with a buffer, or an object of the same type.

        Arguments:
            value: The object to set up current object buffer.

        Returns:
            ``None`` if succeeded, or the type of ``value``.
        """
        if isinstance(value, (str, bytes, bytearray)):
            b = _need_bytes(value)
            if len(b) > self._len:
                raise ValueError(f'Setting bytes larger than {_type(self)}')
            self._view[:] = b.ljust(self._len, b'\x00')
        elif type(self) is type(value):
            self._view[:] = value._view[:]
        else:
            return type(value)
        return None

    @staticmethod
    def _calc_align(typ: CType) -> int:
        """
        Calculates the required align on C level of ``typ``. For basic C types, the
        align is basically equal to the size of the type. As for composite types, the
        align is the max align in members.
        """
        if issubclass(typ, CTYPE_BASE):
            return PwnType._calc_size(typ)
        align_attr = f'_{context.bits}_align_cache_'
        if hasattr(typ, align_attr):
            return getattr(typ, align_attr)
        if issubclass(typ, (CStruct, CUnion)):
            align = max(PwnType._calc_align(f[1]) for f in typ._fields_)
        elif issubclass(typ, CArray):
            if hasattr(typ, '_align_'):  # here _align_ is type-range
                align = typ._align_
            else:
                align = PwnType._calc_align(typ._type_)
        elif issubclass(typ, CEnum):
            align = PwnType._calc_align(typ._size_type_)
        else:
            raise NotImplementedError
        setattr(typ, align_attr, align)
        return align

    @staticmethod
    def _calc_size(typ: CType | PwnType) -> int:
        """
        Calculate how many bytes does ``typ`` takes. For ``CStruct``, if coder manually
        set all struct member offsets, it is considered that the struct is packed, or
        else the struct size will align up. (The default not-packed bahavior.)
        """
        if not isinstance(typ, type):
            typ = type(typ)
        if issubclass(typ, CTYPE_BASE):
            return context.bytes if typ in VAR_TYPES else sizeof(typ)
        cache_attr = f'_{context.bits}_size_cache_'
        if hasattr(typ, cache_attr):
            return getattr(typ, cache_attr)
        if issubclass(typ, CStruct):
            struct_len = 0
            offset_table_attr = f'_offsets{context.bits}_'
            offsets: dict[str, int] = {}
            is64b = context.bits == 64
            maybe_packed = True
            for field in typ._fields_:
                field_t = field[1]
                if len(field) == 4:
                    offset = field[2] if is64b else field[3]
                else:  # offset need to be calculated
                    maybe_packed = False
                    f_align = PwnType._calc_align(field_t)
                    # align up struct_len
                    offset = ((struct_len + f_align - 1) // f_align) * f_align
                offsets[field[0]] = offset
                field_len = PwnType._calc_size(field_t)
                struct_len = max(struct_len, offset + field_len)
            setattr(typ, offset_table_attr, offsets)
            if not maybe_packed:
                align = PwnType._calc_align(typ)
                struct_len = ((struct_len + align - 1) // align) * align
            size_cache = struct_len
        elif issubclass(typ, CArray):
            if typ._count_ == 0:
                return 0
            if hasattr(typ, '_align_'):
                size_cache = typ._align_ * typ._count_
            else:
                size_cache = PwnType._calc_size(typ._type_) * typ._count_
        elif issubclass(typ, CUnion):
            size_cache = max(PwnType._calc_size(field[1]) for field in typ._fields_)
        elif issubclass(typ, CEnum):
            size_cache = PwnType._calc_size(typ._size_type_)
        else:
            raise NotImplementedError
        setattr(typ, cache_attr, size_cache)
        return size_cache

    @staticmethod
    def _print_to_stream(s: TextIOBase, v: bool, indent: int, o: PwnType) -> None:
        """
        Recursively print composite into an IO stream.

        Arguments:
            s: The stream to write into.
            v: ``True`` if writing for ``repr``, ``False`` if writing for ``str``.
            indent: The current indentation.
            o: The composite object to write.
        """
        step = 2 if v else 0
        if isinstance(o, CCharArray):
            s.write('<')
            if not v:
                s.write(bytes(o._view).hex(' '))
            elif o._len > 16:
                _verbose_separator(s, v)
                indent += step
                for i in range(0, o._int_count, 16):
                    s.write(' ' * indent)
                    b = bytes(o._view[i : i + 16])
                    s.write(b.hex(' ').ljust(49))
                    s.write('|')
                    s.writelines(chr(e) if 0x20 <= e < 0x7F else '.' for e in b)
                    s.write('|')
                    _separator(s, v)
                indent -= step
                s.write(' ' * indent)
            else:
                b = bytes(o._view)
                s.write(b.hex(' '))
                s.write('  |')
                s.writelines(chr(e) if 0x20 <= e < 0x7F else '.' for e in b)
                s.write('|')
            s.write('>,')
            _separator(s, v)
        elif isinstance(o, CArray):
            s.write('[')
            _verbose_separator(s, v)
            indent += step
            for i in range(o._int_count):
                s.write(' ' * indent)
                if o._components:
                    PwnType._print_to_stream(s, v, indent, o._components[i])
                else:
                    off = i * o._align_
                    unpacked = unpack(
                        bytes(o._view[off : off + o._int_size]),
                        o._int_size * 8,
                    )
                    s.write(f'{unpacked:#x},')
                    _separator(s, v)
            _remove_non_verbose_tail(s, v)
            indent -= step
            s.write(' ' * indent)
            s.write('],')
            _separator(s, v)
        elif isinstance(o, CStruct):
            # use max offset as width
            w = max(len(hex(off)) for off in o._int_offsets.values()) + 1
            s.write('{')
            _verbose_separator(s, v)
            indent += step
            for field, value in o._components.items():
                off = o._int_offsets[field]
                s.write(' ' * indent)
                if v:
                    s.write(f'{off:<+#{w}x} {field} = ')
                if isinstance(value, PwnType):
                    PwnType._print_to_stream(s, v, indent, value)
                else:  # isinstance(value[0], int)
                    unpacked = unpack(
                        bytes(o._view[off : off + value]),
                        value * 8,
                    )
                    s.write(f'{unpacked:#x},')
                    _separator(s, v)
            _remove_non_verbose_tail(s, v)
            indent -= step
            s.write(' ' * indent)
            s.write('},')
            _separator(s, v)
        elif isinstance(o, CUnion):
            s.write('{')
            _verbose_separator(s, v)
            indent += step
            for field, value in o._components.items():
                s.write(' ' * indent)
                if v:
                    s.write(f'{field} = ')
                if isinstance(value, PwnType):
                    PwnType._print_to_stream(s, v, indent, value)
                else:  # isinstance(value, int)
                    unpacked = unpack(bytes(o._view[:value]), value * 8)
                    s.write(f'{unpacked:#x},')
                    _separator(s, v)
            _remove_non_verbose_tail(s, v)
            indent -= step
            s.write(' ' * indent)
            s.write('},')
            _separator(s, v)
        elif isinstance(o, CEnum):
            s.write(repr(o) if v else str(o))
            s.write(',')
            _separator(s, v)
        else:
            raise NotImplementedError

    def __str__(self) -> str:
        with StringIO() as s:
            PwnType._print_to_stream(s, False, 0, self)
            s.truncate(s.tell() - 2)  # strip comma and separator
            return s.getvalue()

    def __repr__(self) -> str:
        with StringIO() as s:
            PwnType._print_to_stream(s, True, 0, self)
            s.truncate(s.tell() - 2)  # strip comma and separator
            return s.getvalue()

    def __len__(self) -> int:
        return self._len

    def __bytes__(self) -> bytes:
        return bytes(self._view)

    def __eq__(self, value: object, /) -> bool:
        if isinstance(value, (str, bytes, bytearray)):
            return self._view == _need_bytes(value)
        if not isinstance(value, PwnType) or type(self) is not type(value):
            return False
        return self._view == value._view

    def _get_slice(self, subscript: Any) -> bytes | None:
        """
        A helper method to allow user to get object's underlying memory with ``slice``.
        """
        if isinstance(subscript, slice):
            if subscript.step is not None:
                raise ValueError(f'Slice step is not supported')
            start = subscript.start
            stop = subscript.stop
            if start is None:
                start = 0
            elif start < 0:
                start += self._len
            elif start > self._len:
                start = self._len
            if stop is None:
                stop = self._len
            elif stop < 0:
                stop += self._len
            elif stop > self._len:
                stop = self._len
            if start < 0 or stop < 0:
                raise ValueError(f'Illegal index on memoryview')
            if start >= stop:
                raise ValueError(f'Illegal access range on memoryview')
            return bytes(self._view[start:stop])
        return None

    def _set_slice(self, subscript: Any, value: Any) -> bool:
        """
        A helper method to allow user to set object's underlying memory with ``slice``
        and a buffer with the same size as the object.
        """
        if isinstance(subscript, slice):
            if subscript.step is not None:
                raise ValueError(f'Slice step is not supported')
            start = subscript.start
            stop = subscript.stop
            if start is None:
                start = 0
            elif start < 0:
                start += self._len
            elif start > self._len:
                start = self._len
            if stop is None:
                stop = self._len
            elif stop < 0:
                stop += self._len
            elif stop > self._len:
                stop = self._len
            if start < 0 or stop < 0:
                raise ValueError(f'Illegal index on memoryview')
            if start >= stop:
                raise ValueError(f'Illegal access range on memoryview')

            if not isinstance(value, (bytes, bytearray, str)):
                raise ValueError(f"Can't fill memory with {_type(value)}")
            data = _need_bytes(value)
            if len(data) > stop - start:
                raise ValueError(f'Filling bytes larger than sliced memory')
            self._view[start:stop] = data.ljust(stop - start, b'\x00')
            return True
        return False

    def __getitem__(self, key: Any) -> bytes | CompCValue | None:
        return self._get_slice(key)

    def __setitem__(self, key: Any, value: Any) -> None:
        self._set_slice(key, value)


class CArray(PwnType, Generic[ArrayItemT]):
    r"""
    A generic array to implement statments like ``int arr[3];`` in C. An array can be
    accessed with ``int`` subscript. ``slice`` is used to access underlying memory not
    objects.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> class Int4(CArray):
        ...     _type_ = c_int
        ...     _count_ = 4
        ...
        >>> buf = bytearray(32)
        >>> arr = Int4(memoryview(buf))
        >>> arr[0] = 0x13371337
        >>> arr[5:9] = b'\xde\xad\xbe\xef'
        >>> buf[:20]
        bytearray(b'7\x137\x13\x00\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        >>> bytes(arr)[:len(arr)]
        b'7\x137\x13\x00\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00'
        >>> len(arr)
        16
        >>> arr
        [
          0x13371337,
          0xbeadde00,
          0xef,
          0x0,
        ]
        >>> print(arr)
        [0x13371337, 0xbeadde00, 0xef, 0x0]
        >>> arr[2:6]
        b'7\x13\x00\xde'
        >>> arr[1]
        3199065600
    """

    _type_: CType
    """
    The type of elements in array.
    """
    _count_: int
    """
    The count of elements in array. This value can be ``0`` if and only if the array is
    constructed with a ``memoryview``, and the length of that memoryview is not ``0``.
    An internal count will be calculated in that case so user still have bound
    restrictions when accessing elements.
    """
    _align_: int
    """
    Optional special align for the array.
    """
    _int_size: int
    _int_count: int
    _components: list[PwnType] | None

    def __init__(self, view: memoryview | None = None) -> None:
        if not hasattr(self, '_type_') or not hasattr(self, '_count_'):
            raise NotImplementedError
        super().__init__(view)
        if self._len == 0:
            if self._buf is not None:
                raise BufferError('Allocating zero-length array')
            if len(self._view) == 0:
                raise BufferError('Zero-length array has no writable memory')

        self._int_size = PwnType._calc_size(self._type_)
        if not hasattr(self, '_align_'):
            self._align_ = self._int_size
        if self._len:
            self._int_count = self._count_
        else:
            self._len = len(self._view)
            self._int_count = self._len // self._align_

        if issubclass(self._type_, CTYPE_BASE):
            self._components = None
        else:
            step = self._align_
            assert issubclass(self._type_, PwnType)
            self._components = [
                self._type_(self._view[i * step : i * step + self._int_size])
                for i in range(self._int_count)
            ]

    @overload
    def __getitem__(self, key: slice) -> bytes: ...

    @overload
    def __getitem__(self, key: int) -> ArrayItemT: ...

    def __getitem__(self, key: Any) -> bytes | CompCValue:
        b = self._get_slice(key)
        if b is not None:
            return b
        if isinstance(key, int):
            idx = key
            if idx < 0:
                idx += self._int_count
            if idx >= self._int_count or idx < 0:
                raise IndexError(f'Illegal index on elements')
            if self._components is None:
                start = self._align_ * idx
                end = start + self._int_size
                return unpack(
                    bytes(self._view[start:end]),
                    self._int_size * 8,
                )
            # isinstance(self._components, list)
            return self._components[idx]
        raise ValueError(f"Can not access struct with '{_type(key)}' subscript")

    @overload
    def __setitem__(self, key: slice, value: BytesLike) -> None: ...

    @overload
    def __setitem__(self, key: int, value: BytesLike | CompCValue) -> None: ...

    def __setitem__(self, key: Any, value: Any) -> None:
        if self._set_slice(key, value):
            return

        if isinstance(key, int):
            idx = key
            if idx < 0:
                idx += self._int_count
            if idx >= self._int_count or idx < 0:
                raise IndexError(f'Illegal index on elements')
            if self._components is None:
                start = self._align_ * idx
                end = start + self._int_size
                if not isinstance(value, int):
                    raise ValueError(f"Can't set int with {_type(value)}")
                self._view[start:end] = pack(value, self._int_size * 8)
            else:
                # isinstance(self._components, list[PwnType])
                # a.k.a. isinstance(self._type_, PwnType)
                typ = self._components[idx]._copy_from(value)
                if typ is not None:
                    expected = self._type_
                    raise ValueError(f"Can't set {_type(expected)} with {_type(typ)}")
            return

        raise ValueError(f"Can not access array with '{_type(key)}' subscript")

    def _int_iterator(self) -> Iterator[int]:
        """
        A generator function to support iterating ``BaseCType`` ``CArray``.

        Returns:
            An iterator to iterate over underlying ``int`` values.
        """
        for i in range(self._int_count):
            off = i * self._align_
            bits = self._int_size * 8
            yield unpack(bytes(self._view[off : off + self._int_size]), bits)

    @overload
    def __iter__(self: CArray[int]) -> Iterator[int]: ...

    @overload
    def __iter__(self: CArray[ArrayItemT]) -> Iterator[ArrayItemT]: ...

    def __iter__(self) -> Iterator[CompCValue]:
        if self._components is None:
            return self._int_iterator()
        return iter(self._components)


class CCharArray(CArray[int]):
    """
    A specific array type targeting char array. Set variable with this type will print
    hexdump of elements.
    """

    _type_ = c_char


class CStruct(PwnType):
    r"""
    Base type of C structure. A structure can be accessed like member, or ``dict``.
    See examples below.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> class CString(CStruct):
        ...     _fields_ = [
        ...         ('size', c_uint),
        ...         ('flag', c_char, 3, 3),
        ...         ('string', c_char_p),
        ...     ]
        ...     # recommends adding type hints to enable LSP auto completion
        ...     size: int
        ...     flag: int
        ...     string: int
        ...
        >>> context.clear(arch='amd64')
        >>> cstr = CString()
        >>> cstr.size = 0x12345678
        >>> cstr.flag
        18
        >>> cstr.string = 0x7f9843040440
        >>> cstr
        {
          +0x0 size = 0x12345678,
          +0x3 flag = 0x12,
          +0x8 string = 0x7f9843040440,
        }
        >>> bytes(cstr)
        b'xV4\x12\x00\x00\x00\x00@\x04\x04C\x98\x7f\x00\x00'
        >>> len(cstr)
        16
        >>> print(cstr)
        {0x12345678, 0x12, 0x7f9843040440}
        >>> cstr2 = CString(memoryview(b'xV4\x12\x00\x00\x00\x00@\x04\x04C\x98\x7f\x00\x00'))
        >>> cstr == cstr2
        True
        >>> cstr == b'xV4\x12\x00\x00\x00\x00@\x04\x04C\x98\x7f\x00\x00'
        True
        >>> cstr['flag'] = 0xab
        >>> cstr[3:4]
        b'\xab'
        >>> hex(cstr['size'])
        '0xab345678'
        >>> cstr.str
        Traceback (most recent call last):
        ...
        AttributeError: 'CString' object has no attribute 'str'
        >>> cstr['str']
        Traceback (most recent call last):
        ...
        AttributeError: 'CString' object has no attribute 'str'
        >>> cstr.offsetof('flag')
        3
        >>> cstr.offsetof('length')
        Traceback (most recent call last):
        ...
        ValueError: 'length' is not exist in 'CString'
        >>> cstr.struntil('string')
        b'xV4\xab\x00\x00\x00\x00'
    """

    _fields_: list[tuple[str, CType] | tuple[str, CType, int, int]]
    """
    A ``list`` of struct members. If the struct is not packed, and you would like to
    calculate offsets automatically, then fill out members with 2-element tuples,
    member name and the member type.

    If the struct is packed, you would need to fill out all members with 4-element
    tuples, member name, member type, offset for 64-bit targets and offset for 32-bit
    targets.

    Please refer to ``CStruct`` for examples.
    """
    _components: OrderedDict[str, CompCValue]
    _len: int
    _offsets32_: dict[str, int]
    _offsets64_: dict[str, int]
    _int_offsets: dict[str, int]

    def __init__(self, view: memoryview | None = None) -> None:
        if not hasattr(self, '_fields_'):
            raise NotImplementedError
        super().__init__(view)

        self._int_offsets = getattr(self, f'_offsets{context.bits}_')
        self._components = OrderedDict()
        for field in self._fields_:
            field_t = field[1]
            off = self._int_offsets[field[0]]
            if issubclass(field_t, CTYPE_BASE):
                self._components[field[0]] = PwnType._calc_size(field[1])
            else:
                size = PwnType._calc_size(field_t)
                assert issubclass(field_t, PwnType)
                if issubclass(field_t, CArray) and size == 0:
                    self._components[field[0]] = field_t(self._view[off:])
                else:
                    self._components[field[0]] = field_t(self._view[off : off + size])

    def __setattr__(self, name: str, value: Any, /) -> None:
        if '_components' not in self.__dict__ or name not in self._components:
            object.__setattr__(self, name, value)
            return
        rhs = self._components[name]
        if isinstance(rhs, int):
            off = self._int_offsets[name]
            if isinstance(value, int):
                self._view[off : off + rhs] = pack(value, rhs * 8)
            elif isinstance(value, (str, bytes, bytearray)):
                b = _need_bytes(value)
                if len(b) > rhs:
                    raise ValueError(f'Setting bytes larger than {_type(self)}.{name}')
                self._view[off : off + rhs] = b.ljust(rhs, b'\x00')
            else:
                raise ValueError(f"Can't set {_type(self)}.{name} with {_type(value)}")
        else:  # isinstance(rhs, PwnType)
            typ = rhs._copy_from(value)
            if typ is not None:
                raise ValueError(f"Can't set {_type(self)}.{name} with {_type(typ)}")

    def __getattr__(self, name: str) -> CompCValue:
        if '_components' not in self.__dict__ or name not in self._components:
            raise AttributeError(f"'{_type(self)}' object has no attribute '{name}'")
        rhs = self._components[name]
        off = self._int_offsets[name]
        if isinstance(rhs, int):
            return unpack(bytes(self._view[off : off + rhs]), rhs * 8)
        return self._components[name]  # PwnType

    @overload
    def __getitem__(self, key: slice) -> bytes: ...

    @overload
    def __getitem__(self, key: str) -> CompCValue: ...

    def __getitem__(self, key: Any) -> bytes | CompCValue:
        b = self._get_slice(key)
        if b is not None:
            return b
        if isinstance(key, str):
            return getattr(self, key)

        raise ValueError(f"Can not access struct with '{_type(key)}' subscript")

    @overload
    def __setitem__(self, key: slice, value: BytesLike) -> None: ...

    @overload
    def __setitem__(self, key: str, value: BytesLike | CompCValue) -> None: ...

    def __setitem__(self, key: Any, value: Any) -> None:
        if self._set_slice(key, value):
            return

        if isinstance(key, str):
            setattr(self, key, value)
            return

        raise ValueError(f"Can not access struct with '{_type(key)}' subscript")

    def offsetof(self, field_name: str) -> int:
        """
        Get the offset of some member from struct start.

        Arguments:
            field_name: The name of a member exists in the struct.

        Returns:
            The offset from start.

        Raises:
            ValueError: ``field_name`` is not exist in the struct.
        """
        if field_name not in self._components:
            raise ValueError(f"'{field_name}' is not exist in '{_type(self)}'")
        return self._int_offsets[field_name]

    def struntil(self, field_name: str) -> bytes:
        """
        Get sealed buffer until the member.

        Arguments:
            field_name: The name of a member exists in the struct.

        Returns:
            A ``bytes`` slice starts from struct beginning and ends at the member. The
            member is excluded.

        Raises:
            ValueError: ``field_name`` is not exist in the struct.
        """
        if field_name not in self._components:
            raise ValueError(f"'{field_name}' is not exist in '{_type(self)}'")
        return bytes(self._view[: self._int_offsets[field_name]])


class CUnion(PwnType):
    r"""
    Base type of C union. Like struct, you can access members with dot or like
    ``dict``. See examples below.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> class XU(CUnion):
        ...     _fields_ = [
        ...         ('a', c_uint),
        ...         ('b', c_char),
        ...         ('c', c_longlong),
        ...     ]
        ...
        >>> xu = XU()
        >>> xu.c = 0x123456789abcdef0
        >>> xu['b']
        240
        >>> xu.b = 0
        >>> xu.a
        2596068864
        >>> xu
        {
          a = 0x9abcde00,
          b = 0x0,
          c = 0x123456789abcde00,
        }
        >>> print(xu)
        {0x9abcde00, 0x0, 0x123456789abcde00}
        >>> bytes(xu)
        b'\x00\xde\xbc\x9axV4\x12'
        >>> xu[:]
        b'\x00\xde\xbc\x9axV4\x12'
        >>> len(xu)
        8
        >>> xu[:1] = b'123'
        Traceback (most recent call last):
        ...
        ValueError: Filling bytes larger than sliced memory
        >>> xu[0] = b'123'
        Traceback (most recent call last):
        ...
        ValueError: Can not access struct with 'int' subscript
        >>> xu[-99:] = b'123'
        Traceback (most recent call last):
        ...
        ValueError: Illegal index on memoryview
        >>> xu.b = 9999
        Traceback (most recent call last):
        ...
        ValueError: pack(): number does not fit within word_size [0, 9999, 256]
    """

    _fields_: list[tuple[str, CType]]
    """
    A ``list`` of types in the union. The type is described in a ``tuple``, the first
    element is member name, and the secone one is member type.
    """
    _components: OrderedDict[str, CompCValue]

    def __init__(self, view: memoryview | None = None) -> None:
        if not hasattr(self, '_fields_'):
            raise NotImplementedError
        super().__init__(view)

        self._components = OrderedDict()
        for field in self._fields_:
            field_t = field[1]
            if issubclass(field_t, CTYPE_BASE):
                self._components[field[0]] = PwnType._calc_size(field_t)
            else:
                size = PwnType._calc_size(field_t)
                assert issubclass(field_t, PwnType)
                self._components[field[0]] = field_t(self._view[:size])

    def __getattr__(self, name: str) -> CompCValue:
        if '_components' not in self.__dict__ or name not in self._components:
            raise AttributeError(f"'{_type(self)}' object has no attribute '{name}'")
        rhs = self._components[name]
        if isinstance(rhs, int):
            return unpack(bytes(self._view[:rhs]), rhs * 8)
        return self._components[name]  # PwnType

    def __setattr__(self, name: str, value: Any, /) -> None:
        if '_components' not in self.__dict__ or name not in self._components:
            object.__setattr__(self, name, value)
            return
        rhs = self._components[name]
        if isinstance(rhs, int):
            if isinstance(value, int):
                self._view[:rhs] = pack(value, rhs * 8)
            elif isinstance(value, (str, bytes, bytearray)):
                b = _need_bytes(value)
                if len(b) > rhs:
                    raise ValueError(f'Setting bytes larger than {_type(self)}.{name}')
                self._view[:rhs] = b.ljust(rhs, b'\x00')
            else:
                raise ValueError(f"Can't set {_type(self)}.{name} with {_type(value)}")
        else:  # isinstance(rhs, PwnType)
            typ = rhs._copy_from(value)
            if typ is not None:
                raise ValueError(f"Can't set {_type(self)}.{name} with {_type(typ)}")

    @overload
    def __getitem__(self, key: slice) -> bytes: ...

    @overload
    def __getitem__(self, key: str) -> CompCValue: ...

    def __getitem__(self, key: Any) -> bytes | CompCValue:
        b = self._get_slice(key)
        if b is not None:
            return b

        if isinstance(key, str):
            return getattr(self, key)

        raise ValueError(f"Can not access struct with '{_type(key)}' subscript")

    @overload
    def __setitem__(self, key: slice, value: BytesLike) -> None: ...

    @overload
    def __setitem__(self, key: str, value: BytesLike | CompCValue) -> None: ...

    def __setitem__(self, key: Any, value: Any) -> None:
        if self._set_slice(key, value):
            return

        if isinstance(key, str):
            setattr(self, key, value)
            return

        raise ValueError(f"Can not access struct with '{_type(key)}' subscript")


class CEnum(PwnType):
    r"""
    Base type of a C enum. This can be used to beautify struct output.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> from enum import IntEnum
        >>> class XEnum(IntEnum):
        ...     X1 = 1
        ...     X2 = 2
        ...
        >>> class X(CEnum):
        ...     _size_type_ = c_int
        ...     _disp_type_ = XEnum
        ...
        >>> Xarr = mk_anonymous_carray(X, 1)
        >>> e = Xarr()
        >>> e[0] = 1
        >>> e[0]
        0x1 <XEnum.X1: 1>
        >>> print(e[0])
        0x1 <XEnum.X1>
        >>> e[0] = 233
        >>> e[0]
        0xe9
        >>> int(e[0])
        233
    """

    _size_type_: CType
    """
    Defines how many bytes this enum takes.
    """
    _disp_type_: type[IntEnum]
    """
    The internal ``IntEnum`` type for display. When accessing the ``CEnum``, a new
    ``IntEnum`` will be initialized to resolve the value on the memory.
    """

    def __init__(self, view: memoryview | None = None) -> None:
        if not hasattr(self, '_size_type_') or not hasattr(self, '_disp_type_'):
            raise NotImplementedError
        super().__init__(view)
        self._disp_type_.__str__ = Enum.__str__  # type: ignore[method-assign]

    def __getitem__(self, key: slice) -> bytes:
        b = self._get_slice(key)
        if b is not None:
            return b
        raise ValueError(f"'{_type(key)}' is not supported to access '{_type(self)}'")

    def __setitem__(self, key: slice, value: BytesLike) -> None:
        if self._set_slice(key, value):
            return
        raise ValueError(f"'{_type(key)}' is not supported to access '{_type(self)}'")

    def _copy_from(self, value: Any) -> type[Any] | None:
        typ = super()._copy_from(value)
        if typ is None:
            return typ
        if isinstance(value, int):
            self._view[:] = pack(value, self._len * 8)
            return None
        return typ

    def __int__(self) -> int:
        return unpack(bytes(self._view), self._len * 8)

    def __eq__(self, value: object, /) -> bool:
        if isinstance(value, int):
            return int(self) == value
        return super().__eq__(value)

    def __str__(self) -> str:
        val = int(self)
        try:
            member = self._disp_type_(val)
        except ValueError:
            return hex(val)
        return f'{val:#x} <{member!s}>'

    def __repr__(self) -> str:
        val = int(self)
        try:
            member = self._disp_type_(val)
        except ValueError:
            return hex(val)
        return f'{val:#x} {member!r}'


class CFlag(CEnum):
    """
    Base type of a C flag. This can be used to beautify struct output.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> from enum import IntFlag
        >>> class XFlag(IntFlag):
        ...     X1 = 1
        ...     X2 = 2
        ...
        >>> class X(CFlag):
        ...     _size_type_ = c_int
        ...     _disp_type_ = XFlag
        ...
        >>> Xarr = mk_anonymous_carray(X, 1)
        >>> f = Xarr()
        >>> f[0] = 1
        >>> f[0]
        0x1 <XFlag.X1: 1>
        >>> f[0] = XFlag.X2
        >>> print(f[0])
        0x2 <XFlag.X2>
        >>> int(f[0])
        2
    """

    _size_type_: CType
    """
    Defines how many bytes this flag takes.
    """
    _disp_type_: type[IntFlag]
    """
    The internal ``IntFlag`` type for display. When accessing the ``CFlag``, a new
    ``IntFlag`` will be initialized to resolve the value on the memory.
    """

    def __init__(self, view: memoryview | None = None) -> None:
        super().__init__(view)
        self._disp_type_.__str__ = Flag.__str__  # type: ignore[method-assign]

    def __str__(self) -> str:
        val = int(self)
        return f'{val:#x} <{self._disp_type_(val)!s}>'

    def __repr__(self) -> str:
        val = int(self)
        return f'{val:#x} {self._disp_type_(val)!r}'


def mk_anonymous_carray(
    elem_type: CType,
    count: int,
    align: int = 0,
) -> type[CArray[CompCValue]]:
    """
    Factory function to generate an anonymous ``CArray``.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> mk_anonymous_carray(c_int, 2)()
        [
          0x0,
          0x0,
        ]
    """
    fields: dict[str, Any] = {'_type_': elem_type, '_count_': count}
    if align:
        fields['_align_'] = align
    return type(f'AnonymousCArray[{_type(elem_type)}]', (CArray,), fields)


def mk_anonymous_cchararray(count: int) -> type[CCharArray]:
    """
    Factory function to generate an anonymous ``CCharArray``.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> mk_anonymous_cchararray(5)(memoryview(b'hello'))
        <68 65 6c 6c 6f  |hello|>
    """
    fields: dict[str, Any] = {'_type_': c_char, '_count_': count}
    return type('AnonymousCCharArray', (CCharArray,), fields)


def mk_anonymous_cstruct(
    fields: list[tuple[str, CType] | tuple[str, CType, int, int]],
) -> type[CStruct]:
    """
    Factory function to generate an anonymous ``CStruct``.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> mk_anonymous_cstruct([('aaa', c_int)])()
        {
          +0x0 aaa = 0x0,
        }
    """
    return type('AnonymousCStruct', (CStruct,), {'_fields_': fields})


def mk_anonymous_cunion(fields: list[tuple[str, CType]]) -> type[CUnion]:
    """
    Factory function to generate an anonymous ``CUnion``.

    Examples:
        >>> from pwnlib.util.c_primitives import *
        >>> from ctypes import *
        >>> mk_anonymous_cunion([('x', c_int), ('y', c_char)])()
        {
          x = 0x0,
          y = 0x0,
        }
    """
    return type('AnonymousCUnion', (CUnion,), {'_fields_': fields})
