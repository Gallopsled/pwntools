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
        textaddr = elf.offset_to_vaddr(elf.get_section_by_name('.text').header.sh_offset)
        entry = elf.entry
        data = elf.section('.text')[entry-textaddr:]
        mnemonic = elf.pie and 'lea' or 'mov'
        for insn in md.disasm(data, entry):
            if insn.mnemonic == mnemonic:
                if mnemonic == 'lea':
                    addr = insn.address + insn.size + insn.disp
                else:
                    addr = insn.operands[1].imm

                if insn.operands[0].reg == X86_REG_R8:
                    elf.sym['__libc_csu_fini'] = addr
                if insn.operands[0].reg == X86_REG_RCX:
                    elf.sym['__libc_csu_init'] = addr
                    break
            elif insn.mnemonic == 'xor' and insn.operands[0].reg == insn.operands[1].reg == X86_REG_ECX:
                log.error("This binary is compiled for glibc 2.34+ and does not have __libc_csu_init")
            elif insn.mnemonic in ('hlt', 'jmp', 'call', 'syscall'):
                log.error("No __libc_csu_init (no glibc _start)")
        else:
            log.error("Weird _start, definitely no __libc_csu_init")

    # Resolve location of _fini address if required
    if not elf.pie and not call:
        call = next(elf.search(p64(elf.dynamic_by_tag('DT_FINI')['d_ptr'])))
    elif elf.pie and not call:
        log.error("No non-PIE binaries in [elfs], 'call' parameter is required")

    csu_function = elf.read(elf.sym['__libc_csu_init'], elf.sym['__libc_csu_fini'] - elf.sym['__libc_csu_init'])

    # 1st gadget: Populate registers in preparation for 2nd gadget
    for insn in md.disasm(csu_function, elf.sym['__libc_csu_init']):
        if insn.mnemonic == 'pop' and insn.operands[0].reg == X86_REG_RBX:
            rop.raw(insn.address)
            break
    # rbx and rbp must be equal after 'add rbx, 1'
    rop.raw(0x00)  # pop rbx
    rop.raw(0x01)  # pop rbp

    # Older versions of gcc use r13 to populate rdx then r15d to populate edi, newer versions use the reverse
    # Account for this when the binary was linked against a glibc that was built with a newer gcc
    for insn in md.disasm(csu_function, elf.sym['__libc_csu_init']):
        if insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_RDX and insn.operands[1].reg == X86_REG_R13:
            rop.raw(call)  # pop r12
            rop.raw(rdx)  # pop r13
            rop.raw(rsi)  # pop r14
            rop.raw(edi)  # pop r15
            rop.raw(insn.address)
            break
        elif insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_RDX and insn.operands[1].reg == X86_REG_R14:
            rop.raw(edi)  # pop r12
            rop.raw(rsi)  # pop r13
            rop.raw(rdx)  # pop r14
            rop.raw(call)  # pop r15
            rop.raw(insn.address)
            break
        elif insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_RDX and insn.operands[1].reg == X86_REG_R15:
            rop.raw(call)  # pop r12
            rop.raw(edi)  # pop r13
            rop.raw(rsi)  # pop r14
            rop.raw(rdx)  # pop r15
            rop.raw(insn.address)
            break
    else:
        log.error("This CSU init variant is not supported by pwntools")

    # 2nd gadget: Populate edi, rsi & rdx. Populate optional registers
    rop.raw(Padding('<add rsp, 8>'))  # add rsp, 8
    rop.raw(rbx)  # pop rbx
    rop.raw(rbp)  # pop rbp
    rop.raw(r12)  # pop r12
    rop.raw(r13)  # pop r13
    rop.raw(r14)  # pop r14
    rop.raw(r15)  # pop r15
