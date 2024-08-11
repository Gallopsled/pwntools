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

log = getLogger(__name__)



@python_2_bytes_compatible
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

    vars_=[]
    length={}

    __length=0
    size='size'
    name='name'

    variables={
        0:{name:'_IO_read_ptr',size:__length},
        1:{name:'_IO_read_end',size:__length},
        2:{name:'_IO_read_base',size:__length},
        3:{name:'_IO_write_base',size:__length},
        4:{name:'_IO_write_ptr',size:__length},
        5:{name:'_IO_write_end',size:__length},
        6:{name:'_IO_buf_base',size:__length},
        7:{name:'_IO_buf_end',size:__length},
        8:{name:'_IO_save_base',size:__length},
        9:{name:'_IO_backup_base',size:__length},
        10:{name:'_IO_save_end',size:__length},
        11:{name:'_IO_state',size:8},
        12:{name:'_IO_last_state',size:8},
        13:{name:'_codecvt',size:0}, # 32b:0x48, 64b:0x70
        14:{name:'_shortbuf',size:4},
        15:{name:'_wide_vtable',size:__length}
    }

    del name, size, __length


    def update_var(self, l):
        r"""
        Since different members of the WideData structure have different sizes, we need to keep track of the sizes. The following function is used by the WideData class to initialise the lengths of the various fields.

        Arguments:
            l(int)
                l=8 for 'amd64' architecture and l=4 for 'i386' architecture

        Return Value:
            Returns a dictionary in which each field is mapped to its corresponding length according to the architecture set

        Examples:

            >>> wide = WideData()
            >>> wide.update_var(8)
            {'_IO_read_ptr': 8, '_IO_read_end': 8, '_IO_read_base': 8, '_IO_write_base': 8, '_IO_write_ptr': 8, '_IO_write_end': 8, '_IO_buf_base': 8, '_IO_buf_end': 8, '_IO_save_base': 8, '_IO_backup_base': 8, '_IO_save_end': 8, '_IO_state': 8, '_IO_last_state': 8, '_codecvt': 112, '_shortbuf': 4, '_wide_vtable': 8}
        """
        var={}
        for i in self.variables:
            var[self.variables[i]['name']]=self.variables[i]['size']
        for i in var:
            if var[i]<=0:
                var[i]+=l
        if l==4:
            var['_codecvt'] = 0x48
        else:
            var['_codecvt'] = 0x70
        return var


    def __init__(self, null=0):
            self.vars_ = [self.variables[i]['name'] for i in sorted(self.variables.keys())]
            self.setdefault(null)
            self.length = self.update_var(context.bytes)

    def __setattr__(self,item,value):
        if item in WideData.__dict__ or item in self.vars_:
            object.__setattr__(self,item,value)
        else:
            log.error("Unknown variable %r" % item)

    def __repr__(self):
        structure=[]
        for i in self.vars_:
            if isinstance(e, bytes):
                structure.append(" %s: %s" % {i, e})
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

