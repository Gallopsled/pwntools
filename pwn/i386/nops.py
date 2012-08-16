table = [
    ('37', '', 0, 'eax'),         # aaa
    ('d5', '', 1),                # aad
    ('d4', '', 1),                # aam
    ('10', '_<', 0),              # adc r/m8, r8
    ('11', '-<', 0),              # adc r/m32, r32
    ]

def modrm(r, rm):
    return chr(192 + (r << 3) + rm)

regs = {'eax' : 0,
        'ecx' : 1,
        'edx' : 2,
        'ebx' : 3,
        'esp' : 4,
        'ebp' : 5,
        'esi' : 6,
        'edi' : 7}

def nops():
    res = []
    for x in table:
        opcode, mrm, imm = x[:3]
        clobber = [regs[x] for x in x[3:]]
        opcode = opcode.decode('hex')

        if mrm:
            x = mrm[1]
            if   mrm[0] == '_': # 8 bit
                if   x == '<': # r/m is dst
                    for r in range(8):
                        for rm in range(8):
                            res.append((opcode + modrm(r, rm), imm, clobber + [rm % 4]))
                elif x == '>': # r/m is src
                    for r in range(8):
                        for rm in range(8):
                            res.append((opcode + modrm(r, rm), imm, clobber + [r % 4]))
                elif x == '+':
                    for r in range(8):
                        res.append((opcode + chr(ord(mrm[:-2].decode('hex')) + r), imm, clobber + [r % 4]))
                else:
                    for rm in range(8):
                        res.append(opcode + modrm(int(x), imm, clobber + [r % 4]))
            elif mrm[0] == '-': # 32 bit
                if   x == '<': # r/m is dst
                    for r in range(8):
                        for rm in range(8):
                            res.append((opcode + modrm(r, rm), imm, clobber + [rm]))
                elif x == '>': # r/m is src
                    for r in range(8):
                        for rm in range(8):
                            res.append((opcode + modrm(r, rm), imm, clobber + [r]))
                elif x == '+':
                    for r in range(8):
                        res.append((opcode + chr(ord(mrm[:-2].decode('hex')) + r), imm, clobber + [r]))
                else:
                    for rm in range(8):
                        res.append(opcode + modrm(int(x), imm, clobber + [r]))
        else:
            res.append((opcode, imm, clobber))
    return res

print repr(nops())
