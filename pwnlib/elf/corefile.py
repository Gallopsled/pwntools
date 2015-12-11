import ctypes
import elftools
from elftools.common.utils import roundup, struct_parse
from elftools.common.py3compat import bytes2str
from elftools.construct import CString

from .elf import ELF
from .datatypes import *

types = {
    'i386': elf_prstatus_i386,
    'amd64': elf_prstatus_amd64,
}

# Slightly modified copy of the pyelftools version of the same function,
# until they fix this issue:
# https://github.com/eliben/pyelftools/issues/93
def iter_notes(self):
    """ Iterates the list of notes in the segment.
    """
    offset = self['p_offset']
    end = self['p_offset'] + self['p_filesz']
    while offset < end:
        note = struct_parse(
            self._elfstructs.Elf_Nhdr,
            self.stream,
            stream_pos=offset)
        note['n_offset'] = offset
        offset += self._elfstructs.Elf_Nhdr.sizeof()
        self.stream.seek(offset)
        # n_namesz is 4-byte aligned.
        disk_namesz = roundup(note['n_namesz'], 2)
        note['n_name'] = bytes2str(
            CString('').parse(self.stream.read(disk_namesz)))
        offset += disk_namesz

        desc_data = bytes2str(self.stream.read(note['n_descsz']))
        note['n_desc'] = desc_data
        offset += roundup(note['n_descsz'], 2)
        note['n_size'] = offset - note['n_offset']
        yield note


class Core(ELF):
    def __init__(self, *a, **kw):
        self.prstatus = None

        super(Core, self).__init__(*a, **kw)

        if not self.elftype == 'CORE':
            log.error("%s is not a valid corefile" % e.file.name)

        if not self.arch in ('i386','amd64'):
            log.error("%s does not use a supported corefile architecture" % e.file.name)

        prstatus_type = types[self.arch]

        for segment in self.segments:
            if not isinstance(segment, elftools.elf.segments.NoteSegment):
                continue
            for note in iter_notes(segment):
                if note.n_descsz != ctypes.sizeof(prstatus_type):
                    continue
                self.prstatus = prstatus_type.from_buffer_copy(note.n_desc)

    def __getattr__(self, attribute):
        if self.prstatus:
            if hasattr(self.prstatus, attribute):
                return getattr(self.prstatus, attribute)

            if hasattr(self.prstatus.pr_reg, attribute):
                return getattr(self.prstatus.pr_reg, attribute)

        return super(Core, self).__getattribute__(attribute)
