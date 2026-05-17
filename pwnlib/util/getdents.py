from pwnlib.context import context
from pwnlib.util.packing import unpack
from pwnlib.log import getLogger
from enum import IntEnum

log = getLogger(__name__)

class Dtype(IntEnum):
    DT_UNK = 0
    DT_FIFO = 1
    DT_CHR = 2
    DT_DIR = 4
    DT_BLK = 6
    DT_REG = 8
    DT_LNK = 10
    DT_SOCK = 12
    DT_WHT = 14
    DT_SUBVOL = 16

class linux_dirent:
    """
    Represent struct linux_dirent

    .. code-block:: c

        struct linux_dirent
        {
            unsigned long d_ino;
            unsigned long d_off;
            unsigned short d_reclen;
            char d_name[];
        };
        // https://elixir.bootlin.com/linux/v6.14.4/source/fs/readdir.c#L244
        // the 32version of linux_dirent stores d_type after d_name

        struct linux_dirent64 {
            u64		d_ino;
            s64		d_off;
            unsigned short	d_reclen;
            unsigned char	d_type;
            char		d_name[];
        };
        // https://elixir.bootlin.com/linux/v6.14.4/source/include/linux/dirent.h#L5

        enum
        {
            DT_UNKNOWN = 0,
            DT_FIFO = 1,
            DT_CHR = 2,
            DT_DIR = 4,
            DT_BLK = 6,
            DT_REG = 8,
            DT_LNK = 10,
            DT_SOCK = 12,
            DT_WHT = 14,
            DT_SUBVOL = 16
        };
        // https://elixir.bootlin.com/linux/v6.14.4/source/include/linux/fs_types.h#L42
        // https://elixir.bootlin.com/linux/v6.14.4/source/fs/bcachefs/dirent_format.h#L37
    """

    d_ino: int
    d_off: int
    d_reclen: int
    d_type: Dtype
    d_name: str

    def __init__(self, buf: bytes, is_dirent64: bool):
        size_t = 8 if is_dirent64 else context.bytes

        self.d_ino = unpack(buf[0:size_t], size_t * 8)
        self.d_off = unpack(buf[size_t : 2 * size_t], size_t * 8)
        self.d_reclen = unpack(buf[2 * size_t : 2 * size_t + 2], 16)

        if is_dirent64:
            d_type = unpack(buf[2 * size_t + 2 : 2 * size_t + 3], 8)
            d_name = buf[2 * size_t + 3 : self.d_reclen - 1]
        else:
            d_type = unpack(buf[self.d_reclen - 1 : self.d_reclen], 8)
            d_name = buf[2 * size_t + 2 : self.d_reclen - 1]

        self.d_name = d_name.split(b'\x00', 1)[0].decode('utf-8')
        self.d_type = Dtype(d_type)

    def __len__(self):
        return self.d_reclen

    def __str__(self):
        return self.d_name

    def __repr__(self):
        return f'{self.d_type.name:<8}{self.d_name}'


def dirents(buf: bytes) -> list[linux_dirent]:
    """dirents(buf: bytes) -> list[linux_dirent]:

    Extracts data from a buffer emitted by getdents

    Arguments:
        buf(bytes): getdents result

    Returns:
        A list of file names

    Example:
        >>> with context.local(bytes = 4):
        ...     buf = bytes.fromhex('5e843600c120fc1a1400746573742e63000000085f8436001f347e3010002e00be36ba040d002c00ffffff7f10002e2e00000004')
        ...     print(dirents(buf))
        ...     
        [DT_REG  test.c, DT_DIR  ., DT_DIR  ..]
    """

    bpos = 0
    buf_len = len(buf)
    entries = []

    while bpos < buf_len:
        try:
            dirent = linux_dirent(buf[bpos:], False)
            bpos += dirent.d_reclen
            entries.append(dirent)
        except (ValueError, UnicodeDecodeError):
            log.warning("Failed to parse struct linux_dirent at position %d", bpos)
            break
    return entries

def dirents64(buf: bytes) -> list[linux_dirent]:
    """dirents(buf: bytes) -> list[linux_dirent]:

    Extracts data from a buffer emitted by getdents64

    Arguments:
        buf(bytes): getdents64 result

    Returns:
        A list of file names

    Example:
        >>> with context.local(bytes = 8):
        ...     buf = bytes.fromhex('223a2c0000000000786a631cc120fc1a200008746573742e63007464040000000d002c00000000004802ee451f347e301800042e0000000002002c0000000000ffffffffffffff7f1800042e2e000000')
        ...     print(dirents64(buf))
        ...     
        [DT_REG  test.c, DT_DIR  ., DT_DIR  ..]
    """

    bpos = 0
    buf_len = len(buf)
    entries = []

    while bpos < buf_len:
        try:
            dirent = linux_dirent(buf[bpos:], True)
            bpos += dirent.d_reclen
            entries.append(dirent)
        except (ValueError, UnicodeDecodeError):
            log.warning("Failed to parse struct linux_dirent64 at position %d", bpos)
            break
    return entries
