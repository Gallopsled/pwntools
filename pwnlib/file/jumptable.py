# -*- coding: utf-8 -*-

r"""
Jump Table in File

In FILE there is a jump table indicates where functions like ``read`` and ``write`` are.
In some FILE exploitations, forced jump table is needed to hijack the control flow.
For example, in **House of Apple**, one of the paths is ``exit -> fcloseall -> _IO_cleanup -> _IO_flush_all_lockp -> _IO_wstrn_overflow``

Like FileStructure, this file helps you to create exploitation gracefully.

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
class JumpTable(object):
    r"""
    Crafts a Jump Table, with all fields are set to 0.

    Examples:

        Jump Table with _doallocate is set to 0x7f34df678f7a

        >>> context.clear(arch='amd64')
        >>> jmpTable = JumpTable()
        >>> jmpTable._doallocate = 0x7f34df678f7a
        >>> payload = bytes(jmpTable)
        >>> payload
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x8fg\xdf4\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        Check the length of the JumpTable

        >>> len(jmpTable)
        168

        The definition for __repr__ orders the structure members and displays then in a dictionary format. It's useful when viewing a structure objet in python/IPython shell

        >>> jmpTable
        { _dummy: 0x0
         _dummy2: 0x0
         _finish: 0x0
         _overflow: 0x0
         _underflow: 0x0
         _uflow: 0x0
         _pbackfail: 0x0
         _xsputn: 0x0
         _xsgetn: 0x0
         _seekoff: 0x0
         _seekpos: 0x0
         _setbuf: 0x0
         _sync: 0x0
         _doallocate: 0x7f34df678f7a
         _read: 0x0
         _write: 0x0
         _seek: 0x0
         _close: 0x0
         _stat: 0x0
         _showmanyc: 0x0
         _imbue: 0x0}
    """

    vars_=[]
    length={}

    __length=0
    size='size'
    name='name'

    variables={
        0:{name:'_dummy',size:__length},
        1:{name:'_dummy2',size:__length},
        2:{name:'_finish',size:__length},
        3:{name:'_overflow',size:__length},
        4:{name:'_underflow',size:__length},
        5:{name:'_uflow',size:__length},
        6:{name:'_pbackfail',size:__length},
        7:{name:'_xsputn',size:__length},
        8:{name:'_xsgetn',size:__length},
        9:{name:'_seekoff',size:__length},
        10:{name:'_seekpos',size:__length},
        11:{name:'_setbuf',size:__length},
        12:{name:'_sync',size:__length},
        13:{name:'_doallocate',size:__length},
        14:{name:'_read',size:__length},
        15:{name:'_write',size:__length},
        16:{name:'_seek',size:__length},
        17:{name:'_close',size:__length},
        18:{name:'_stat',size:__length},
        19:{name:'_showmanyc',size:__length},
        20:{name:'_imbue',size:__length}
    }

    del name, size, __length


    def update_var(self, l):
        r"""
        Since different members of the file structure have different sizes, we need to keep track of the sizes. The following function is used by the FileStructure class to initialise the lengths of the various fields.

        Arguments:
            l(int)
                l=8 for 'amd64' architecture and l=4 for 'i386' architecture

        Return Value:
            Returns a dictionary in which each field is mapped to its corresponding length according to the architecture set

        Examples:

            >>> table = JumpTable()
            >>> table.update_var(8)
            {'_dummy': 8, '_dummy2': 8, '_finish': 8, '_overflow': 8, '_underflow': 8, '_uflow': 8, '_pbackfail': 8, '_xsputn': 8, '_xsgetn': 8, '_seekoff': 8, '_seekpos': 8, '_setbuf': 8, '_sync': 8, '_doallocate': 8, '_read': 8, '_write': 8, '_seek': 8, '_close': 8, '_stat': 8, '_showmanyc': 8, '_imbue': 8}
        """
        var={}
        for i in self.variables:
            var[self.variables[i]['name']]=self.variables[i]['size']
        for i in var:
            if var[i]<=0:
                var[i]+=l
        return var

    def __init__(self):
            self.vars_ = [self.variables[i]['name'] for i in sorted(self.variables.keys())]
            self.setdefault()
            self.length = self.update_var(context.bytes)

    def __setattr__(self,item,value):
        if item in JumpTable.__dict__ or item in self.vars_:
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
                structure += getattr(self, val).ljust(context.bytes, b'\x00')
            else:
                if self.length[val] > 0:
                    structure += pack(getattr(self, val), self.length[val]*8)
        return structure

    def struntil(self,v):
        r"""
        Payload for stuff till 'v' where 'v' is a structure member. This payload includes 'v' as well.

        Arguments:
            v(string)
                The name of the field uptil which the payload should be created.

        Usage is just like the same function in FileStructure. Check it out if you need an example.
        """
        if v not in self.vars_:
            return b''
        structure = b''
        for val in self.vars_:
            if isinstance(getattr(self, val), bytes):
                structure += getattr(self, val).ljust(context.bytes, b'\x00')
            else:
                structure += pack(getattr(self, val), self.length[val]*8)
            if val == v:
                break
        return structure[:-1]

    def setdefault(self):
            self._dummy = 0
            self._dummy2 = 0
            self._finish = 0
            self._overflow = 0
            self._underflow = 0
            self._uflow = 0
            self._pbackfail = 0
            self._xsputn = 0
            self._xsgetn = 0
            self._seekoff = 0
            self._seekpos = 0
            self._setbuf = 0
            self._sync = 0
            self._doallocate = 0
            self._read = 0
            self._write = 0
            self._seek = 0
            self._close = 0
            self._stat = 0
            self._showmanyc = 0
            self._imbue = 0
