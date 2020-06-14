from __future__ import division
import six

# +------------------------------------------------------------------------+ 
# |                        ARM Instructions                                | 
# +------------------------------------------------------------------------+ 


EOR = 1
SUB = 2
RSB = 3
MI  = 4
PL  = 5 
LDR = 6
STR = 7
LDM = 8
STM = 9
ROR = 10
LSR = 11

# (EOR/SUB/RSB)(PL/MI){S} rd, rn, #imm 
# ====================================
def dpimm(op, cond, s, d, n, imm):
    x = bytearray()
    if isinstance(imm, six.integer_types):
        x.append(imm & 0xff)
    else:
        x.append(imm)
    x.append((d << 4) & 0xff)
    x.append(op << 5 | s << 4 | n)
    x.append(cond << 4 | 2)
    return bytes(x)

# (EOR/SUB/RSB)PL{S} rd, rn, ra ROR #imm 
# ======================================
def dpshiftimm(op, s, d, n, a, imm):
    x = bytearray()
    x.append(0x60 | a)
    x.append(((d << 4)| (imm >> 1)) & 0xff)
    x.append(op << 5 | s << 4 | n)
    x.append(PL << 4)
    return bytes(x)

# (EOR/SUB/RSB)PL{S} rd, rn, ra (ROR/LSR) rb 
# ==========================================
def dpshiftreg(op, s, d, n, a, shift, b):
    x = bytearray()
    if shift == LSR:
        x.append(0x30 | a)
    else:
        x.append(0x70 | a)
    x.append(((d << 4) | b) & 0xff)
    x.append(op << 5 | s << 4 | n)
    x.append(PL << 4)
    return bytes(x)

# (LDR/STR)(PL/MI)B rd, [rn, #-imm] 
# =================================
def lsbyte(op, cond, d, n, imm):
    x = bytearray()
    if isinstance(imm, six.integer_types):
        x.append(imm & 0xff)
    else:
        x.append(imm)
    x.append((d << 4) & 0xff)
    if op == STR:
        x.append(0x40 | n)
    else:
        x.append(0x50 | n)
    x.append(cond << 4 | 5)
    return bytes(x)

# STMPLFD rd, (Register List)^ 
# ============================
def smul(d, reglH, reglL):
    return bytes(bytearray((reglL, reglH, 0x40 | d, 0x59)))

# LDMPLDB rn!, (Register List) 
# ============================
def lmul(n, reglH, reglL):
    return bytes(bytearray((reglL, reglH, 0x30 | n, 0x59)))

# SWI(PL/MI) 0x9f0002 
# ==============
def swi(cond):
    x = bytearray(b"\x02\x00\x9f")
    x.append(cond << 4 | 0xf)
    return bytes(x)

# BMI 0xfffff4 
# ============
def bmi():
    return b"\xf4\xff\xff\x4b"

# STRPLB rd, [!rn, -(rm ROR #imm)] with P=0 i.e. post-indexed addressing mode 
# ===========================================================================
def sbyteposti(d, n, m, imm):
    x = bytearray()
    x.append(0x60 | m)
    x.append(((d << 4) | (imm >> 1)) & 0xff)
    x.append(0x40 | n)
    x.append(PL << 4 | 6)
    return bytes(x)
