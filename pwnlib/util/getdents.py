from ..context import context
from .fiddling import hexdump
from .packing import unpack


class linux_dirent(object):
    def __init__(self, buf):
        n = context.bytes

        # Long
        self.d_ino    = unpack(buf[:n])
        buf=buf[n:]

        # Long
        self.d_off    = unpack(buf[:n])
        buf=buf[n:]

        # Short
        self.d_reclen = unpack(buf[:2], 16)
        buf=buf[2:]

        # Name
        self.d_name = buf[:buf.index('\x00')]

    def __len__(self):
        return self.d_reclen # 2 * context.bytes + 2 + len(self.d_name) + 1

    def __str__(self):
        return "inode=%i %r" % (self.d_ino, self.d_name)

def dirents(buf):
    """unpack_dents(buf) -> list

    Extracts data from a buffer emitted by getdents()

    Arguments:
        buf(str): Byte array

    Returns:
        A list of filenames.

    Example:

        >>> data = '5ade6d010100000010002e0000000004010000000200000010002e2e006e3d04092b6d010300000010007461736b00045bde6d010400000010006664003b3504'
        >>> data = data.decode('hex')
        >>> print dirents(data)
        ['.', '..', 'fd', 'task']
    """
    d = []

    while buf:
        try:
            ent = linux_dirent(buf)
        except ValueError:
            break
        d.append(ent.d_name)
        buf = buf[len(ent):]

    return sorted(d)
