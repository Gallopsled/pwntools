from __future__ import absolute_import
from __future__ import division

from capstone import *
from capstone.x86 import *

from .rop import Padding
from ..log import getLogger
from ..util.packing import p64


log = getLogger(__name__)


def ret2csu(rop, elf, edi, rsi, rdx, rbx, rbp, r12, r13, r14, r15, call=None):
    """Build a ret2csu ROPchain

    Arguments:
        edi, rsi, rdx: Three primary registers to populate
        rbx, rbp, r12, r13, r14, r15: Optional registers to populate
        call: Pointer to the address of a function to call during
            second gadget. If None then use the address of _fini in the
            .dynamic section. .got.plt entries are a good target. Required
            for PIE binaries.
    """

    # Prepare capstone
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True

    # Resolve __libc_csu_ symbols if candidate binary is stripped
    if '__libc_csu_init' not in elf.symbols:
        if elf.pie:
            for insn in md.disasm(elf.section('.text'),
                                  elf.offset_to_vaddr(elf.get_section_by_name('.text').header['sh_offset'])):
                if insn.mnemonic == 'lea' and insn.operands[0].reg == X86_REG_R8:
                    elf.sym['__libc_csu_fini'] = insn.address + insn.size + insn.disp
                if insn.mnemonic == 'lea' and insn.operands[0].reg == X86_REG_RCX:
                    elf.sym['__libc_csu_init'] = insn.address + insn.size + insn.disp
                    break
        else:
            for insn in md.disasm(elf.section('.text'), elf.get_section_by_name('.text').header['sh_addr']):
                if insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_R8:
                    elf.sym['__libc_csu_fini'] = insn.operands[1].imm
                if insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_RCX:
                    elf.sym['__libc_csu_init'] = insn.operands[1].imm
                    break

    # Resolve location of _fini address if required
    if not elf.pie and not call:
        fini = next(elf.search(p64(elf.dynamic_by_tag('DT_FINI')['d_ptr'])))
    elif elf.pie and not call:
        log.error('No non-PIE binaries in [elfs], \'call\' parameter is required')

    csu_function = elf.read(elf.sym['__libc_csu_init'], elf.sym['__libc_csu_fini'] - elf.sym['__libc_csu_init'])

    # 1st gadget: Populate registers in preparation for 2nd gadget
    for insn in md.disasm(csu_function, elf.sym['__libc_csu_init']):
        if insn.mnemonic == 'pop' and insn.operands[0].reg == X86_REG_RBX:
            rop.raw(insn.address)
            break
    # rbx and rbp must be equal after 'add rbx, 1'
    rop.raw(0x00)  # pop rbx
    rop.raw(0x01)  # pop rbp
    if call:
        rop.raw(call)  # pop r12
    else:
        rop.raw(fini)  # pop r12

    # Older versions of gcc use r13 to populate rdx then r15d to populate edi, newer versions use the reverse
    # Account for this when the binary was linked against a glibc that was built with a newer gcc
    for insn in md.disasm(csu_function, elf.sym['__libc_csu_init']):
        if insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_RDX and insn.operands[1].reg == X86_REG_R13:
            rop.raw(rdx)  # pop r13
            rop.raw(rsi)  # pop r14
            rop.raw(edi)  # pop r15
            rop.raw(insn.address)
            break
        elif insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_RDX and insn.operands[1].reg == X86_REG_R15:
            rop.raw(edi)  # pop r13
            rop.raw(rsi)  # pop r14
            rop.raw(rdx)  # pop r15
            rop.raw(insn.address)
            break

    # 2nd gadget: Populate edi, rsi & rdx. Populate optional registers
    rop.raw(Padding('<add rsp, 8>'))  # add rsp, 8
    rop.raw(rbx)  # pop rbx
    rop.raw(rbp)  # pop rbp
    rop.raw(r12)  # pop r12
    rop.raw(r13)  # pop r13
    rop.raw(r14)  # pop r14
    rop.raw(r15)  # pop r15
