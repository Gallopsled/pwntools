from collections import OrderedDict
from ctypes import (
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
from typing import Any

from pwnlib.context import context
from pwnlib.util.packing import _need_bytes, pack, unpack

CTYPE_BASE = c_long.__base__
VAR_TYPES = [c_void_p, c_char_p, c_wchar_p, c_size_t, c_ssize_t, c_ulong, c_long]


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
        s.truncate(s.tell() - 2)


class PwnType:
    _32_size_cache_: int
    _64_size_cache_: int
    _buf: bytearray | None
    _view: memoryview
    _len: int

    def __init__(self, view: memoryview | None) -> None:
        self._len = PwnType.calc_size(self)
        if view is None:
            self._buf = bytearray(self._len)
            self._view = memoryview(self._buf)
        else:
            self._buf = None
            self._view = view

    def copy_from(self, value: Any) -> None | type:
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
    def calc_align(typ: type) -> int:
        if issubclass(typ, CTYPE_BASE):
            return PwnType.calc_size(typ)
        align_attr = f'_{context.bits}_align_cache_'
        if hasattr(typ, align_attr):
            return getattr(typ, align_attr)
        if issubclass(typ, (CStruct, CUnion)):
            align = max(PwnType.calc_align(f[1]) for f in typ._fields_)
        elif issubclass(typ, CArray):
            if hasattr(typ, '_align_'):  # here _align_ is type-range
                align = typ._align_
            else:
                align = PwnType.calc_align(typ._type_)
        elif issubclass(typ, (CEnum, CFlag)):
            align = PwnType.calc_align(typ._size_type_)
        else:
            raise NotImplementedError
        setattr(typ, align_attr, align)
        return align

    @staticmethod
    def calc_size(typ: type | PwnType) -> int:
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
            offsets = {}
            is64b = context.bits == 64
            maybe_packed = True
            for field in typ._fields_:
                field_t = field[1]
                if len(field) == 4:
                    offset = field[2] if is64b else field[3]
                else:  # offset need to be calculated
                    maybe_packed = False
                    f_align = PwnType.calc_align(field_t)
                    # align up struct_len
                    offset = ((struct_len + f_align - 1) // f_align) * f_align
                offsets[field[0]] = offset
                field_len = PwnType.calc_size(field_t)
                struct_len = max(struct_len, offset + field_len)
            setattr(typ, offset_table_attr, offsets)
            if not maybe_packed:
                align = PwnType.calc_align(typ)
                struct_len = ((struct_len + align - 1) // align) * align
            size_cache = struct_len
        elif issubclass(typ, CArray):
            if typ._count_ == 0:
                return 0
            size_cache = PwnType.calc_align(typ) * typ._count_
        elif issubclass(typ, CUnion):
            size_cache = max(PwnType.calc_size(field[1]) for field in typ._fields_)
        elif issubclass(typ, (CEnum, CFlag)):
            size_cache = PwnType.calc_size(typ._size_type_)
        else:
            raise NotImplementedError
        setattr(typ, cache_attr, size_cache)
        return size_cache

    @staticmethod
    def print_to_stream(s: TextIOBase, v: bool, indent: int, o: PwnType) -> None:
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
                    PwnType.print_to_stream(s, v, indent, o._components[i])
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
                    PwnType.print_to_stream(s, v, indent, value)
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
                    PwnType.print_to_stream(s, v, indent, value)
                else:  # isinstance(value, int)
                    unpacked = unpack(bytes(o._view[:value]), value * 8)
                    s.write(f'{unpacked:#x},')
                    _separator(s, v)
            _remove_non_verbose_tail(s, v)
            indent -= step
            s.write(' ' * indent)
            s.write('},')
            _separator(s, v)
        elif isinstance(o, (CFlag, CEnum)):
            s.write(repr(o) if v else str(o))
            s.write(',')
            _separator(s, v)
        else:
            raise NotImplementedError

    def __str__(self) -> str:
        with StringIO() as s:
            PwnType.print_to_stream(s, False, 0, self)
            s.truncate(s.tell() - 2)  # strip comma and separator
            return s.getvalue()

    def __repr__(self) -> str:
        with StringIO() as s:
            PwnType.print_to_stream(s, True, 0, self)
            s.truncate(s.tell() - 2)  # strip comma and separator
            return s.getvalue()

    def __len__(self) -> int:
        return self._len

    def __bytes__(self) -> bytes:
        return bytes(self._view)

    def __eq__(self, value: object, /) -> bool:
        if type(self) is not type(value):
            return False
        return self._view == value._view

    def __getitem__(self, subscript: Any) -> None | bytes:
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

    def __setitem__(self, subscript: Any, value: Any) -> bool:
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


class CArray(PwnType):
    _type_: type
    _count_: int
    _align_: int
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

        self._int_size = PwnType.calc_size(self._type_)
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
            self._components = [
                self._type_(self._view[i * step : i * step + self._int_size])
                for i in range(self._int_count)
            ]

    def __getitem__(self, subscript: int | slice) -> Any:
        b = super().__getitem__(subscript)
        if b is not None:
            return b
        if isinstance(subscript, int):
            idx = subscript
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
        raise ValueError(f"Can not access struct with '{_type(subscript)}' subscript")

    def __setitem__(self, subscript: int | slice, value: Any) -> None:
        if super().__setitem__(subscript, value):
            return

        if isinstance(subscript, int):
            idx = subscript
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
                typ = self._components[idx].copy_from(value)
                if typ is not None:
                    expected = self._type_
                    raise ValueError(f"Can't set {_type(expected)} with {_type(typ)}")
            return

        raise ValueError(f"Can not access array with '{_type(subscript)}' subscript")


class CCharArray(CArray):
    _type_ = c_char


class CStruct(PwnType):
    _fields_: list[tuple[str, type, int, int] | tuple[str, type]]
    _components: OrderedDict[str, int | PwnType]
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
                self._components[field[0]] = PwnType.calc_size(field[1])
            else:
                size = PwnType.calc_size(field_t)
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
            typ = rhs.copy_from(value)
            if typ is not None:
                raise ValueError(f"Can't set {_type(self)}.{name} with {_type(typ)}")

    def __getattr__(self, name: str) -> Any:
        if '_components' not in self.__dict__ or name not in self._components:
            raise AttributeError(f"'{_type(self)}' object has no attribute '{name}'")
        rhs = self._components[name]
        off = self._int_offsets[name]
        if isinstance(rhs, int):
            return unpack(bytes(self._view[off : off + rhs]), rhs * 8)
        return self._components[name]  # PwnType

    def __getitem__(self, subscript: str | slice) -> Any:
        b = super().__getitem__(subscript)
        if b:
            return b
        if isinstance(subscript, str):
            return getattr(self, subscript)

        raise ValueError(f"Can not access struct with '{_type(subscript)}' subscript")

    def __setitem__(self, subscript: str | slice, value: Any) -> None:
        if super().__setitem__(subscript, value):
            return

        if isinstance(subscript, str):
            setattr(self, subscript, value)
            return

        raise ValueError(f"Can not access struct with '{_type(subscript)}' subscript")

    def offsetof(self, field_name: str) -> int:
        if field_name not in self._components:
            raise ValueError(f"'{field_name}' is not exist in '{_type(self)}'")
        return self._int_offsets[field_name]

    def struntil(self, field_name: str) -> bytes:
        if field_name not in self._components:
            raise ValueError(f"'{field_name}' is not exist in '{_type(self)}'")
        return bytes(self._view[: self._int_offsets[field_name]])


class CUnion(PwnType):
    _fields_: list[tuple[str, type]]
    _components: OrderedDict[str, PwnType | int]

    def __init__(self, view: memoryview | None = None) -> None:
        if not hasattr(self, '_fields_'):
            raise NotImplementedError
        super().__init__(view)

        self._components = OrderedDict()
        for field in self._fields_:
            field_t = field[1]
            if issubclass(field_t, CTYPE_BASE):
                self._components[field[0]] = PwnType.calc_size(field_t)
            else:
                size = PwnType.calc_size(field_t)
                self._components[field[0]] = field_t(self._view[:size])

    def __getattr__(self, name: str) -> Any:
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
                if len(b) > rhs[0]:
                    raise ValueError(f'Setting bytes larger than {_type(self)}.{name}')
                self._view[:rhs] = b.ljust(rhs, b'\x00')
            else:
                raise ValueError(f"Can't set {_type(self)}.{name} with {_type(value)}")
        else:  # isinstance(rhs[0], PwnType)
            typ = rhs.copy_from(value)
            if typ is not None:
                raise ValueError(f"Can't set {_type(self)}.{name} with {_type(typ)}")

    def __getitem__(self, subscript: Any) -> Any:
        b = super().__getitem__(subscript)
        if b is not None:
            return b

        if isinstance(subscript, str):
            return getattr(self, subscript)

        raise ValueError(f"Can not access struct with '{_type(subscript)}' subscript")

    def __setitem__(self, subscript: Any, value: Any) -> None:
        if super().__setitem__(subscript, value):
            return

        if isinstance(subscript, str):
            setattr(self, subscript, value)
            return

        raise ValueError(f"Can not access struct with '{_type(subscript)}' subscript")


class CEnum(PwnType):
    _size_type_: type
    _enum_: type[IntEnum]

    def __init__(self, view: memoryview | None = None) -> None:
        if not hasattr(self, '_size_type_') or not hasattr(self, '_enum_'):
            raise NotImplementedError
        super().__init__(view)
        self._enum_.__str__ = Enum.__str__

    def __getitem__(self, subs: Any) -> None | bytes:
        b = super().__getitem__(subs)
        if b is not None:
            return b
        raise ValueError(f"'{_type(subs)}' is not supported to access '{_type(self)}'")

    def __setitem__(self, subs: Any, value: Any) -> None:
        if super().__setitem__(subs, value):
            return
        raise ValueError(f"'{_type(subs)}' is not supported to access '{_type(self)}'")

    def copy_from(self, value: Any) -> None | type:
        typ = super().copy_from(value)
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
        if val in self._enum_:
            return f'{val:#x} <{self._enum_(val)!s}>'
        return hex(val)

    def __repr__(self) -> str:
        val = int(self)
        if val in self._enum_:
            return f'{val:#x} {self._enum_(val)!r}'
        return hex(val)


class CFlag(PwnType):
    _size_type_: type
    _flag_: type[IntFlag]

    def __init__(self, view: memoryview | None = None) -> None:
        if not hasattr(self, '_size_type_') or not hasattr(self, '_flag_'):
            raise NotImplementedError
        super().__init__(view)
        self._flag_.__str__ = Flag.__str__

    def __getitem__(self, subs: Any) -> None | bytes:
        b = super().__getitem__(subs)
        if b is not None:
            return b
        raise ValueError(f"'{_type(subs)}' is not supported to access '{_type(self)}'")

    def __setitem__(self, subs: Any, value: Any) -> None:
        if super().__setitem__(subs, value):
            return
        raise ValueError(f"'{_type(subs)}' is not supported to access '{_type(self)}'")

    def copy_from(self, value: Any) -> None | type:
        typ = super().copy_from(value)
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
        return f'{val:#x} <{self._flag_(val)!s}>'

    def __repr__(self) -> str:
        val = int(self)
        return f'{val:#x} {self._flag_(val)!r}'


def mk_anonymous_carray(elem_type: type, count: int, align: int = 0) -> type[CArray]:
    fields = {'_type_': elem_type, '_count_': count}
    if align:
        fields['_align_'] = align
    return type('', (CArray,), fields)


def mk_anonymous_cchararray(count: int, align: int = 0) -> type[CCharArray]:
    fields = {'_type_': c_char, '_count_': count}
    if align:
        fields['_align_'] = align
    return type('', (CCharArray,), fields)


def mk_anonymous_cstruct(
    fields: list[tuple[str, type] | tuple[str, type, int, int]],
) -> type[CStruct]:
    return ('', (CStruct,), {'_fields_': fields})


def mk_anonymous_cunion(fields: list[tuple[str, type]]) -> type[CUnion]:
    return ('', (CUnion,), {'_fields_': fields})
