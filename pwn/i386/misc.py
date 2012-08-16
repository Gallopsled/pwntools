from random import randint, randrange

def nops(n, **opts):
    if 'saved' in opts:
        saved = opts['saved']
    else:
        saved = []
    if 'avoid' in opts:
        avoid = opts['avoid']
    else:
        avoid = []

    eax, ebx, ecx, edx, esi, edi, ebp, esp = 'eax ebx ecx edx esi edi ebp esp'.split()

    regs32 = [eax, ecx, edx, ebx, esp, ebp, esi, edi]
    regs8  = [eax, ecx, edx, ebx, eax, ecx, edx, ebx]

    def randreg32():
        while True:
            r = randint(0, 7)
            if regs32[r] not in saved:
                return r

    def randreg8():
        while True:
            r = randint(0, 7)
            if regs8[r] not in saved:
                return r

    def randbyte():
        while True:
            c = chr(randint(0, 255))
            if c not in avoid:
                return c

    def modrm(r, rm):
        return chr(192 + (r << 3) + rm)

    def gen(xs):
        res = []
        for i in range(0, len(xs), 2):
            x = xs[i + 1]
            if   xs[i] == '_': # 8 bit
                if   x == 'b':
                    res.append(randbyte())
                elif x == '<': # r/m is dst
                    res.append(modrm(randint(0, 7), randreg8()))
                elif x == '>': # r/m is src
                    res.append(modrm(randreg8(), randint(0, 7)))
                else:
                    res.append(modrm(int(x), randreg8()))

            elif xs[i] == '-': # 32 bit
                if   x == '<': # r/m is dst
                    res.append(modrm(randint(0, 7), randreg32()))
                elif x == '>': # r/m is src
                    res.append(modrm(randreg32(), randint(0, 7)))
                else:
                    res.append(modrm(int(x), randreg32()))

            else:
                b = xs[i:i+2].decode('hex')
                if b in avoid:
                    return None
                res.append(b)

        return ''.join(res)

    # _  : 8bit
    # -  : 32bit
    # <  : r/m dst
    # >  : r/m src
    # b  : imm8

    table = [
        ('37', eax),         # aaa
        ('d5_b', eax),       # aad
        ('d4_b', eax),       # aam
        ('3f', eax),         # aas
        ('14_b', eax),       # adc al, imm8
        ('15_b_b_b_b', eax), # adc eax, imm32
        ('80_2_b'),          # adc r/m8, imm8
        ('81-2_b_b_b_b'),    # adc r/m32, imm32
        ('83-2_b'),          # adc r/m32, imm8
        ('10_<'),            # adc r/m8, r8
        ('11-<'),            # adc r/m32, r32
        ('12_>'),            # adc r8, r/m8
        ('13->'),            # adc r32, r/m32
        ('04_b', eax),       # add al, imm8
        ('05_b_b_b_b', eax), # add eax, imm32
        ('80_0_b'),          # add r/m8, imm8
        ('81-0_b_b_b_b'),    # add r/m32, imm32
        ('83-0_b'),          # add r/m32, imm8
        ('00_<'),            # add r/m8, r8
        ('01-<'),            # add r/m32, r32
        ('02_>'),            # add r8, r/m8
        ('03->'),            # add r32, r/m32
        ('24_b', eax),       # and al, imm8
        ('25_b', eax),       # and eax, imm32
        ('80_4_b'),          # and r/m8, imm8
        ('81-4_b_b_b_b'),    # and r/m32, imm32
        ('83-4_b'),          # and r/m32, imm8
        ('20_<'),            # and r/m8, r8
        ('21-<'),            # and r/m32, r32
        ('22_>'),            # and r8, r/m8
        ('23->'),            # and r32, r/m32
        
        ('90')               # nop
        ]

    res = []
    while n > 0:
        xs = table[randrange(0, len(table))]
        if type(xs) == tuple:
            if any(map(lambda r: r in saved, xs[1:])):
                continue
            xs = xs[0]
        if len(xs) / 2 > n:
            continue
        print 'foo'
        xs = gen(xs)
        if xs is None:
            continue
        print 'bar'
        if any(map(lambda x: x in avoid, xs)):
            continue
        print xs.encode('hex')
        res.append(xs)
        n -= len(xs)
    return ''.join(res)
