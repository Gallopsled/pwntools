

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
   if type(imm) == int:
      x = chr(imm & 0xff)
   else:
      x = imm
   x += chr((d << 4) & 0xff)
   if s:
      if op == EOR:
         x += chr(0x30 | n)
      if op == SUB:
         x += chr(0x50 | n)
      if op == RSB:
         x += chr(0x70 | n)
   else:
      if op == SUB:
         x += chr(0x40 | n)
      if op == RSB:
         x += chr(0x60 | n)
   if cond == PL:
      x += "\x52"
   else:
      x += "\x42"
   return x
   
# (EOR/SUB/RSB)PL{S} rd, rn, ra ROR #imm 
# ====================================== 
def dpshiftimm(op, s, d, n, a, imm):
   x = chr(0x60 | a)
   x += chr(((d << 4)| (imm >> 1)) & 0xff)
   if s:
      if op == EOR:
         x += chr(0x30 | n)
      if op == SUB:
         x += chr(0x50 | n)
      if op == RSB:
         x += chr(0x70 | n)
   else:
      if op == SUB:
         x += chr(0x40 | n)
      if op == RSB:
         x += chr(0x60 | n)
   return x + "\x50" 

# (EOR/SUB/RSB)PL{S} rd, rn, ra (ROR/LSR) rb 
# ========================================== 
def dpshiftreg(op, s, d, n, a, shift, b):
   x = ''
   if shift == LSR:
      x += chr(0x30 | a)
   else:
      x += chr(0x70 | a)
   x += chr(((d << 4) | b) & 0xff)
   if s != 0:
      if op == EOR:
         x += chr(0x30 | n)
      if op == SUB:
         x += chr(0x50 | n)
      if op == RSB:
         x += chr(0x70 | n)
   else:
      if op == SUB:
         x += chr(0x40 | n)
      if op == RSB:
         x += chr(0x60 | n)
   return x + "\x50"

# (LDR/STR)(PL/MI)B rd, [rn, #-imm] 
# ================================= 
def lsbyte(op, cond, d, n, imm):
   if type(imm) == int:
      x = chr(imm & 0xff)
   else:
      x = imm
   x += chr((d << 4) & 0xff)
#   x = chr(imm) + chr((d << 4) & 0xff)
   if op == STR:
      x += chr(0x40 | n)
   else:
      x += chr(0x50 | n)
   if cond == PL:
      x += "\x55"
   else:
      x += "\x45"
   return x

# STMPLFD rd, (Register List)^ 
# ============================ 
def smul(d, reglH, reglL):
   return chr(reglL) + chr(reglH) + chr(0x40 | d) + "\x59"

# LDMPLDB rn!, (Register List) 
# ============================ 
def lmul(n, reglH, reglL):
   return chr(reglL) + chr(reglH) + chr(0x30 | n) + "\x59"

# SWI(PL/MI) 0x9f0002 
# ============== 
def swi(cond):
   x = "\x02\x00\x9f"
   if cond == MI:
      x += "\x4f"
   else:
      x += "\x5f"
   return x

# BMI 0xfffff4 
# ============ 
def bmi():
   return "\xf4\xff\xff\x4b"

# STRPLB rd, [!rn, -(rm ROR #imm)] with P=0 i.e. post-indexed addressing mode 
# =========================================================================== 
def sbyteposti(d, n, m, imm):
   x = chr(0x60 | m)
   x += chr(((d << 4) | (imm >> 1)) & 0xff)
   x += chr(0x40 | n)
   x += "\x56"
   return x
