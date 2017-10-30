.. testsetup:: *

   from pwn import *
   from glob import glob
   from pwnlib.elf.maps import CAT_PROC_MAPS_EXIT

:mod:`pwnlib.elf.elf` --- ELF Files
===========================================================

.. automodule:: pwnlib.elf.elf

  .. autoclass:: pwnlib.elf.elf.ELF
     :members:
     :show-inheritance:
     :inherited-members:
     :exclude-members: address_offsets,
                       get_data,
                       get_dwarf_info,
                       get_section,
                       get_segment,
                       has_dwarf_info,
                       iter_sections,
                       iter_segments

  .. autoclass:: pwnlib.elf.elf.Function
     :members:

  .. autoclass:: pwnlib.elf.elf.dotdict
     :members:
