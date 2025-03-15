# -*- coding: utf-8 -*-

r"""
Wide Data Exploitation

Like FILE, IO_wide_file is a struct which deals ``wchar_t`` data.
Later glibc protects FILE by checking the jump table pointer, so it becomes harder to
exploit normal FILE. In newer exploitations like **House of Apple**, due to jump table
in wide data is not checked, so we can construct a fake WideData to exploit.

Remembering the offsets of various structure members while faking a WideData structure can be difficult,
so this python class helps you with that. Example-

>>> context.clear(arch='amd64')
>>> wide = WideData(0xdeadbeef)
>>> wide._IO_write_base = 0xcafebabe
>>> payload = bytes(wide)
>>> payload
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00'

Now payload contains the FILE structure with its vtable pointer pointing to 0xcafebabe

Currently only 'amd64' and 'i386' architectures are supported
"""

from __future__ import absolute_import
from __future__ import division

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.misc import python_2_bytes_compatible
from pwnlib.util.packing import pack
from pwnlib.structs import struct_attr, struct_attr_list

log = getLogger(__name__)

class WideData(object):
    r"""
    Crafts a WideData structure, with all fields are set to 0, except _wide_vtable set to specified "null".

    Arguments:
        null(int)
            A pointer to NULL value in memory (_wide_vtable). This pointer can lie in any segment (stack, heap, bss, libc etc)

    Examples:

        WideData structure with _wide_vtable set to 0x555555553470

        >>> context.clear(arch='amd64')
        >>> wdata = WideData(0x555555553470)

        Check the length of the WideData

        >>> len(wdata)
        228

        The definition for __repr__ orders the structure members and displays then in a dictionary format. It's useful when viewing a structure objet in python/IPython shell

        >>> wide = WideData(0xdeadbeef)
        >>> wide
        { _IO_read_ptr: 0x0
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
         _IO_state: 0x0
         _IO_last_state: 0x0
         _codecvt: 0x0
         _shortbuf: 0x0
         _wide_vtable: 0xdeadbeef}
    """

    VARIABLES = (
        struct_attr('_IO_read_ptr',     0, 8, 0, 4),
        struct_attr('_IO_read_end',     8, 8, 4, 4),
        struct_attr('_IO_read_base',    0x10, 8, 0x8, 4),
        struct_attr('_IO_write_base',   0x18, 8, 0xc, 4),
        struct_attr('_IO_write_ptr',    0x20, 8, 0x10, 4),
        struct_attr('_IO_write_end',    0x28, 8, 0x14, 4),
        struct_attr('_IO_buf_base',     0x30, 8, 0x18, 4),
        struct_attr('_IO_buf_end',      0x38, 8, 0x1c, 4),
        struct_attr('_IO_save_base',    0x40, 8, 0x20, 4),
        struct_attr('_IO_backup_base',  0x48, 8, 0x24, 4),
        struct_attr('_IO_save_end',     0x50, 8, 0x28, 4),
        struct_attr('_IO_state',        0x58, 8, 0x2c, 8),
        struct_attr('_IO_last_state',   0x60, 8, 0x34, 8),
        struct_attr('_codecvt',         0x68, 0x70, 0x3c, 0x48),
        struct_attr('_shortbuf',        0xd8, 4, 0x84, 4),
        struct_attr('_wide_vtable',     0xe0, 8, 0x88, 4),
    )

    def __init__(self, null=0):
        self.vars_ = struct_attr_list(self.VARIABLES, context.bits == 32, log)
        self.setdefault(null)

    def __setattr__(self, item: str, value: any):
        if not self.vars_.check_attr(item, value) and item not in WideData.__dict__:
            log.error(f"Unknown variable {item}")
        object.__setattr__(self, item, value)

    def __repr__(self):
        structure=[]
        for i in self.vars_:
            e = getattr(self, i)
            if isinstance(e, bytes):
                structure.append(" %s: %s" % (i, e))
            else:
                structure.append(" %s: %#x" % (i, e))
        return "{"+ "\n".join(structure)+"}"

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        structure = b''
        for val in self.vars_:
            if isinstance(getattr(self, val), bytes):
                structure += getattr(self, val).ljust(self.length[val], b'\x00')
            else:
                structure += pack(getattr(self, val), self.length[val]*8)
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
            >>> wide = WideData(0xdeadbeef)
            >>> payload = wide.struntil('_IO_buf_base')
            >>> payload
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        """
        if v not in self.vars_:
            return b''
        structure = b''
        for val in self.vars_:
            if isinstance(getattr(self, val), bytes):
                structure += getattr(self, val).ljust(self.length[val], b'\x00')
            else:
                structure += pack(getattr(self, val), self.length[val]*8)
            if val == v:
                break
        return structure[:-1]

    def setdefault(self,null):
            self._IO_read_ptr = 0
            self._IO_read_end = 0
            self._IO_read_base = 0 
            self._IO_write_base = 0
            self._IO_write_ptr = 0
            self._IO_write_end = 0
            self._IO_buf_base = 0
            self._IO_buf_end = 0
            self._IO_save_base = 0
            self._IO_backup_base = 0
            self._IO_save_end = 0
            self._IO_state = 0
            self._IO_last_state = 0
            self._codecvt = 0
            self._shortbuf = 0
            self._wide_vtable = null

