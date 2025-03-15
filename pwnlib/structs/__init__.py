from __future__ import absolute_import

from enum import Enum

from pwnlib.structs.filepointer import *
from pwnlib.structs.widedata import *
from pwnlib.structs.jumptable import *
from pwnlib.util.packing import *

class WideFSOPType(Enum):
    APPLE2_OVERFLOW = 0x20
    APPLE2_MMAP =     0x21
    APPLE2_XSGETN =   0x22
    APPLE3_UNDERFLOW = 0x30
    APPLE3_MMAP =      0x31
    APPLE3_WRITE =     0x32
    APPLE3_SYNC =      0x33

class WideFSOPErrors(Enum):
    FILE_FLAGS =     0
    FILE_READ_PTR =  1
    FILE_MODE =      2
    FILE_WRITE_PTR = 3
    FILE_WRITE_END = 4
    FILE_VTABLE =    5
    FILE_WIDE_DATA = 6
    FILE_CODECVT =   7
    WDATA_WRITE_BASE = 0x10
    WDATA_BUF_BASE =   0x11
    WDATA_READ_PTR =   0x12
    WDATA_SAVE_BASE =  0x13
    WDATA_WRITE_PTR =  0x14
    WDATA_VTABLE =     0x15
    VTABLE_DOALLOCATE = 0x20
    VTABLE_OVERFLOW =   0x21
    CODECVT_CDIN =  0x30
    CODECVT_CDOUT = 0x31
    CDSTEP_STATEFUL = 0x40
    CDSTEP_FCT =      0x41

def validate_wide_FSOP_payload(mode: WideFSOPType, payload: bytes, fileoff: int=None,
                           wideoff: int=None, jumpoff: int=None, codecvtoff: int=None,
                           cdstepoff: int=None, warn_level: str='warn') -> list[WideFSOPErrors]:
    r"""validate_wide_FSOP_payload(mode: WideFSOPType, payload: bytes,
        fileoff: int=None, wideoff: int=None, jumpoff: int=None,
        codecvtoff: int=None, cdstepoff: int=None, warn_level: str='info')
        -> list[WideFSOPErrors]:
    A util function to validate if the payload matches exploit
    conditions of an FSOP that exploits the ``_wide_data`` structure,
    such as House of Apple. This will be useful if you have limited
    bytes to write so you have to overlap structures but the default
    payload can not meet some restrictions and you have to create a
    specific payload. In this case, calling this function saves your
    time to check manually.

    Parameter:
        mode: One of enum values in WideFSOPType to determine how
            to check the payload.
        payload: The actual payload in FSOP part you want to send.
        fileoff: The offset in ``int`` indicating where the FILE
            starts in `payload`. For instance, if `payload` is just
            a fake FILE, then `fileoff` should be ``0``. Set `fileoff`
            to ``None`` if you want to skip the check for it. The
            parameters below follows similar rules.
        wideoff: The offset of WideData in FILE. See `fileoff`.
        jumpoff: The offset of JumpTable in WideData. See `fileoff`.
        codecvtoff: The offset of _codecvt in FILE. See `fileoff`.
        cdstepoff: The offset of ``__cd_*.step`` in _codecvt.
            See `fileoff`.
        warn_level: A string of log level to output some extra info.
            For instance, for ``WideFSOPType.APPLE2_XSGETN``,
            ``rdx`` should NOT be ``0``. As we can not check rdx,
            so we have to log to warn users that ``rdx`` need to
            be checked. The default log level is `warn`.

    Return:
        ``[]`` if all checks passed. If some checks fail, a list
        of ``WideFSOPErrors`` enum values is returned. Basically
        each enum is named according to the house of apple blog.
    """
    length = len(payload)
    amd64 = context.arch == 'amd64'
    MAGIC = 0x100000
    log.setLevel(context.log_level)
    logit = log.__getattribute__(warn_level)

    INT = 32
    PTR = 64
    def _check(goff: int, off64: int, off32: int, len64: int):
        offword, lenword = off64, len64 if amd64 else off32, 32
        offset = goff + offword
        return unpack(payload[offset:offset + lenword], lenword, sign=True) \
                if offset + lenword <= length                               \
                else -1

    if mode is WideFSOPType.APPLE2_XSGETN:
        logit('_IO_wdefault_xsgetn requires rdx to be 0!')

    errs = []
    if fileoff is not None:
        if mode is WideFSOPType.APPLE2_OVERFLOW:
            # flags
            # -1 & any == any, so if structure is not long enough to
            # check, this check will not pass
            if _check(fileoff, 0, 0, INT) & (2 | 8 | 0x800):
                errs.append(WideFSOPErrors.FILE_FLAGS)
        elif mode is WideFSOPType.APPLE2_MMAP:
            # flags
            if _check(fileoff, 0, 0, INT) & 4:
                errs.append(WideFSOPErrors.FILE_FLAGS)
            # read ptr & read end
            ptr = _check(fileoff, 8, 4, PTR)
            end = _check(fileoff, 0x10, 0xc, PTR)
            if ptr >= end or end == -1:
                errs.append(WideFSOPErrors.FILE_READ_PTR)
        elif mode is WideFSOPType.APPLE2_XSGETN:
            # flags
            flags = _check(fileoff, 0, 0, INT)
            if flags == -1 or not flags & 0x800:
                errs.append(WideFSOPErrors.FILE_FLAGS)
            # mode
            if _check(fileoff, 0xc0, 0x68, INT) <= 0:
                errs.append(WideFSOPErrors.FILE_MODE)
        elif mode is WideFSOPType.APPLE3_UNDERFLOW:
            # flags
            if _check(fileoff, 0, 0, INT) & (4 | 0x10):
                errs.append(WideFSOPErrors.FILE_FLAGS)
            # read ptr & read end
            ptr = _check(fileoff, 8, 4, PTR)
            end = _check(fileoff, 0x10, 0xc, PTR)
            if ptr >= end or end == -1:
                errs.append(WideFSOPErrors.FILE_READ_PTR)
        elif mode is WideFSOPType.APPLE3_MMAP:
            # flags
            if _check(fileoff, 0, 0, INT) & 4:
                errs.append(WideFSOPErrors.FILE_FLAGS)
            # read ptr & read end
            ptr = _check(fileoff, 8, 4, PTR)
            end = _check(fileoff, 0x10, 0xc, PTR)
            if ptr >= end or end == -1:
                errs.append(WideFSOPErrors.FILE_READ_PTR)
        elif mode is WideFSOPType.APPLE3_WRITE:
            # write ptr & write base
            if _check(fileoff, 0x28, 0x14, PTR) <= _check(fileoff, 0x20, 0x10, PTR):
                errs.append(WideFSOPErrors.FILE_WRITE_PTR)
            # mode
            if _check(fileoff, 0xc0, 0x68, INT) <= 0:
                errs.append(WideFSOPErrors.FILE_MODE)
            # write end & write ptr; write end & write base
            end = _check(fileoff, 0x30, 0x18, PTR)
            if end == -1 or end == ptr and end != base:
                errs.append(WideFSOPErrors.FILE_WRITE_END)
        elif mode is WideFSOPType.APPLE3_SYNC:
            # flags
            if _check(fileoff, 0, 0, INT) & (4 | 0x10):
                errs.append(WideFSOPErrors.FILE_FLAGS)
        else:
            raise AssertionError('No such mode in WideFSOPType')
        # vtable
        if _check(fileoff, 0xd8, 0x94, PTR) < MAGIC:
            errs.append(WideFSOPErrors.FILE_VTABLE)
        # wide data
        if _check(fileoff, 0xa0, 0x58, PTR) < MAGIC:
            errs.append(WideFSOPErrors.FILE_WIDE_DATA)
        if 0x30 <= mode.value < 0x40: # only apple 3 need this check
            # codecvt
            if _check(fileoff, 0x98, 0x84, PTR) < MAGIC:
                errs.append(WideFSOPErrors.FILE_CODECVT)

    if wideoff is not None:
        if mode is WideFSOPType.APPLE2_OVERFLOW:
            # write base
            if _check(wideoff, 0x18, 0xc, PTR):
                errs.append(WideFSOPErrors.WDATA_WRITE_BASE)
            # buf base
            if _check(wideoff, 0x30, 0x18, PTR):
                errs.append(WideFSOPErrors.WDATA_BUF_BASE)
        elif mode is WideFSOPType.APPLE2_MMAP:
            # read ptr & read end
            # if don't catch -1 here, it will still be catched under
            if _check(wideoff, 0, 0, PTR) < _check(wideoff, 8, 4, PTR):
                errs.append(WideFSOPErrors.WDATA_READ_PTR)
            # buf base
            if _check(wideoff, 0x30, 0x18, PTR):
                errs.append(WideFSOPErrors.WDATA_BUF_BASE)
            # save base
            if _check(wideoff, 0x40, 0x20, PTR):
                logit('_wide_data->_IO_save_base need to be a free-able address')
        elif mode is WideFSOPType.APPLE2_XSGETN:
            # read end & read ptr
            end = _check(wideoff, 8, 4, PTR)
            ptr = _check(wideoff, 0, 0, PTR)
            if end != ptr or ptr == -1:
                errs.append(WideFSOPErrors.WDATA_READ_PTR)
            # write ptr & write base
            ptr = _check(wideoff, 0x20, 0x10, PTR)
            base = _check(wideoff, 0x18, 0xc, PTR)
            if ptr <= base or ptr == -1 or base == -1:
                errs.append(WideFSOPErrors.WDATA_WRITE_PTR)
        elif mode is WideFSOPType.APPLE3_UNDERFLOW:
            # read ptr & read end
            ptr = _check(wideoff, 0, 0, PTR)
            end = _check(wideoff, 8, 4, PTR)
            if ptr < end or end == -1 or ptr == -1:
                errs.append(WideFSOPErrors.WDATA_READ_PTR)
        elif mode is WideFSOPType.APPLE3_MMAP:
            # read ptr & read end
            ptr = _check(wideoff, 0, 0, PTR)
            end = _check(wideoff, 8, 4, PTR)
            if ptr < end or end == -1 or ptr == -1:
                errs.append(WideFSOPErrors.WDATA_READ_PTR)
            # buf base
            base = _check(wideoff, 0x30, 0x18, PTR)
            if base == 0 or base == -1:
                errs.append(WideFSOPErrors.WDATA_BUF_BASE)
        elif mode is WideFSOPType.APPLE3_WRITE:
            # write ptr & write base
            ptr = _check(wideoff, 0x20, 0x10, PTR)
            base = _check(wideoff, 0x18, 0xc, PTR)
            if ptr < base or ptr == -1 or base == -1:
                errs.append(WideFSOPErrors.WDATA_WRITE_PTR)
        elif mode is WideFSOPType.APPLE3_SYNC:
            # write ptr & write base
            ptr = _check(wideoff, 0x20, 0x10, PTR)
            base = _check(wideoff, 0x18, 0xc, PTR)
            if ptr > base or ptr == -1 or base == -1:
                errs.append(WideFSOPErrors.WDATA_WRITE_PTR)
            # read ptr & read end
            if _check(wideoff, 0, 0, PTR) == _check(wideoff, 8, 4, PTR):
                errs.append(WideFSOPErrors.WDATA_READ_PTR)
        else:
            raise AssertionError('No such mode in WideFSOPType')
        if 0x20 <= mode.value < 0x30: # only apple 2 need to check vtable
            if _check(wideoff, 0xe0, 0x88, PTR) < MAGIC:
                errs.append(WideFSOPErrors.WDATA_VTABLE)

    if jumpoff is not None:
        if mode is WideFSOPType.APPLE2_OVERFLOW:
            # doallocate
            if _check(jumpoff, 0x68, 0x34, PTR) < MAGIC:
                errs.append(WideFSOPErrors.VTABLE_DOALLOCATE)
        elif mode is WideFSOPType.APPLE2_MMAP:
            # doallocate
            if _check(jumpoff, 0x68, 0x34, PTR) < MAGIC:
                errs.append(WideFSOPErrors.VTABLE_DOALLOCATE)
        elif mode is WideFSOPType.APPLE2_XSGETN:
            # overflow
            if _check(jumpoff, 0x18, 0xc, PTR) < MAGIC:
                errs.append(WideFSOPErrors.VTABLE_OVERFLOW)

    if codecvtoff is not None:
        if  mode is WideFSOPType.APPLE3_UNDERFLOW or \
            mode is WideFSOPType.APPLE3_MMAP or \
            mode is WideFSOPType.APPLE3_SYNC:
            # __cd_in.step
            if _check(codecvtoff, 0, 0, PTR) < MAGIC:
                errs.append(WideFSOPErrors.CODECVT_CDIN)
        elif mode is WideFSOPType.APPLE3_WRITE:
            # __cd_out.step
            if _check(codecvtoff, 0x38, 0x24, PTR) < MAGIC:
                errs.append(WideFSOPErrors.CODECVT_CDOUT)

    if cdstepoff is not None:
        if mode is WideFSOPType.APPLE3_SYNC:
            # stateful
            stateful = _check(cdstepoff, 0x58, 0x34, INT)
            if stateful == 0 or stateful == -1:
                errs.append(WideFSOPErrors.CDSTEP_STATEFUL)
        # shlib_handle
        if _check(cdstepoff, 0, 0, PTR) != 0:
            logit('shlib_handle is not 0, please deal with PTR_MANGLE')
        # fct
        if _check(cdstepoff, 0x28, 0x14, PTR) < MAGIC:
            errs.append(WideFSOPErrors.CDSTEP_FCT)

    return errs

class struct_attr:
    def __init__(self, name: str, off64: int, len64: int, off32: int, len32: int):
        self.length = (len64, len32)
        self.offset = (off64, off32)
        self.maximum = (1 << len64, 1 << len32)
        self.name = name

    def __eq__(self, obj: str) -> bool:
        return self.name == obj

class struct_attr_list:
    def __init__(self, attrs: tuple[struct_attr], i386: bool, logger):
        self.attrs = attrs
        self.is32bit = int(i386)
        self.log = logger

    def _find(self, attr_name: str) -> struct_attr:
        if attr_name not in self.attrs:
            return None
        return self.attrs[self.attrs.index(attr_name)]

    def get_attr(self, attr_name: str) -> tuple[int, int]:
        attr = self._find(attr_name)
        if attr is None:
            return -1, -1
        return attr.offset[self.is32bit], attr.length[self.is32bit]

    def check_attr(self, attr_name: str, value: any) -> bool:
        attr = self._find(attr_name)
        if attr is None:
            return False
        size = attr.length[self.is32bit]
        if isinstance(value, int):
            maximum = attr.maximum[self.is32bit]
            num = num if num >= 0 else num + maximum
            if num < 0 or num >= (1 << maximum):
                self.log.error(f"Out of bounds for {attr_name}: expect item size {size}, but get {value}")
        elif isinstance(value, (str, bytes)):
            value = _need_bytes(value)
            if len(value) > maxsize:
                self.log.error(f"Value too large for {attr_name}: expect item size {size}, but get {len(value)}")
        elif hasattr(value, '__bytes__') is False:
            self.log.error(f"Unable to cast {attr_name} to bytes")
        # if value can cast to bytes, we don't check its size here
        # as it may be mutable
        return True
