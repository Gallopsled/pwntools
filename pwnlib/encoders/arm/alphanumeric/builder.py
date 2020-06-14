from __future__ import absolute_import
from __future__ import division

from . import alphanum_byte
from .ARM_Instructions import (
    EOR,
    SUB,
    RSB,
    MI,
    PL,
    LDR,
    STR,
    LDM,
    STM,
    ROR,
    LSR,
    dpimm,
    dpshiftimm,
    dpshiftreg,
    swi,
    bmi,
    lmul,
    lsbyte,
    sbyteposti,
)
from . import random_funcs


# +---------------------------------------------------+
# |                Builder Functions                  |
# +---------------------------------------------------+

class builder(object):
    def __init__(self):
        self.I = 0
        self.size = 0
        self.i = 0
        self.j = 0
        self.k = 0
        self.x = 0
        self.addr = 0
        self.addr_offset = 0

    def enc_data_builder(self, input):
        if not input:
            return b''
        output = bytearray()
        self.I = random_funcs.randel(range(1, 10))
        for ab in bytearray(input):
            b = ab & 0x0f
            e0 = random_funcs.enc_data_msn(b, self.I)
            e0 = e0 << 4
            ef = e0 | b
            d = ((ab & 0xf0) ^ e0) >> 4
            c0 = random_funcs.enc_data_msn(d, self.I) << 4
            cd = c0 | d
            output.append(cd & 0xff)
            output.append(ef & 0xff)
        # Last two bytes to stop the decoder_loop
        max = 0x30 | self.I
        output.append(alphanum_byte.alphanumeric_get_byte())
        output.append(alphanum_byte.alphanumeric_get_byte_ltmax(max))
        return bytes(output)

    def DecoderLoopBuilder(self, icache_flush):
        dec_loop = b''
        # Select p,s,t and q
        arr = [3, 7]
        p = random_funcs.randel(arr)
        if p == 3:
            s = 7
        else:
            s = 3
        t = 6
        arr2 = [8, 9]
        q = random_funcs.randel(arr2)

        # Add the instructions
        if icache_flush:
            dec_loop += swi(MI)

        rsalnum = alphanum_byte.alphanumeric_get_byte()

        if icache_flush:
            # EORMIS rp, r4, #(randomly selected alphanumeric value)
            dec_loop += dpimm(EOR, MI, 1, p, 4, rsalnum)

        if icache_flush:
            dist = 0x2c
        else:
            dist = 0x28

        offset = alphanum_byte.off_gen(dist + 0x04)

        # SUBPL rs, r4, #(dist+0x04+offset)
        dec_loop += dpimm(SUB, PL, 0, s, 4, dist + 0x04 + offset)

        # SUBPL rs, pc, rs LSR r4
        dec_loop += dpshiftreg(SUB, 0, s, 0x0f, s, LSR, 4)

        # EORPLS rt, r4, rs LSR r4
        dec_loop += dpshiftreg(EOR, 1, t, 4, s, LSR, 4)

        # EORMIS rp, r4, #rsalnum
        rsalnum = alphanum_byte.alphanumeric_get_byte()
        dec_loop += dpimm(EOR, MI, 1, p, 4, rsalnum)

        # LDRPLB rp, [rs, #(-offset)]
        dec_loop += lsbyte(LDR, PL, p, s, offset)

        # SUBPL rs, rs, r5 LSR r4
        dec_loop += dpshiftreg(SUB, 0, s, s, 5, LSR, 4)

        # LDRPLB rq, [rs, #(-offset)]
        dec_loop += lsbyte(LDR, PL, q, s, offset)

        # EORPLS rp, rq, rp ROR #28
        dec_loop += dpshiftimm(EOR, 1, p, q, p, 28)

        # STRPLB rp, [rt, #(-offset)]
        dec_loop += lsbyte(STR, PL, p, t, offset)

        # SUBPL rt, rt, r5 LSR r4
        dec_loop += dpshiftreg(SUB, 0, t, t, 5, LSR, 4)

        # SUBPL rs, rs, r5 LSR r4
        dec_loop += dpshiftreg(SUB, 0, s, s, 5, LSR, 4)

        # RSBPLS rq, rq, #0x3I
        dec_loop += dpimm(RSB, PL, 1, q, q, 0x30 | self.I)

        # BMI 0xfffff4
        dec_loop += bmi()

        # STRPLB r4, [rt, #-(offset+1)]
        dec_loop += lsbyte(STR, PL, 4, t, offset + 1)

        if icache_flush:
            # SWIPL 0x9f0002
            dec_loop += swi(PL)
        return dec_loop

    def encDecoderLoopBuilder(self, input):
        output = bytearray()
        for p in input:
            if not alphanum_byte.alphanumeric_check(p):
                output.append(alphanum_byte.alphanumeric_get_byte())
            else:
                output.append(p)
        return bytes(output)

    def DecoderBuilder(self, input, icache_flush):
        if not input:
            return b''
        output = b''

        # Register selections
        arr = [4, 6]
        self.addr = random_funcs.randel(arr)
        arr2 = [3, 5, 7]
        self.i = random_funcs.randel(arr2)
        arr3 = [0, 0]
        q = 0
        for p in arr2:
            if p != self.i:
                arr3[q] = p
                q += 1
        self.j = random_funcs.randel(arr3)
        for p in arr3:
            if p != self.j:
                self.k = p
                break

        self.x = alphanum_byte.off_gen(0x01)
        if icache_flush:
            output += self.algo1(input, 0, 3)
            output += self.gap_traverse(0x1e)
            output += self.algo1(input, 33, 5)
        else:
            output += self.gap_traverse(0x19)
            output += self.algo1(input, 25, 5)
        output += self.gap_traverse(0x0f)
        if icache_flush:
            output += self.algo1(input, 53, 15)
        else:
            output += self.algo1(input, 45, 11)
        # trucate the last instruction, which increments raddr by 1, from the output
        output = output[:-4]
        self.size -= 4
        # Setting r0, r1, r2 for parameter passing
        # SUBPLS ri, ri, #x
        output += dpimm(SUB, PL, 1, self.i, self.i, self.x)
        # SUBPL r4, ri, ri LSR ri
        output += dpshiftreg(SUB, 0, 4, self.i, self.i, LSR, self.i)
        # SUBPL r6, ri, ri LSR ri
        output += dpshiftreg(SUB, 0, 6, self.i, self.i, LSR, self.i)
        # SUBPL r5, rj, r4 ROR r6
        output += dpshiftreg(SUB, 0, 5, self.j, 4, ROR, 6)

        self.size += 4 * 4

        if icache_flush:
            arr4 = [3, 7]
            m = random_funcs.randel(arr4)

            c = alphanum_byte.off_gen(24)
            arr5 = range(2, 20, 2)
            arr6 = [4, 6]
            arr7 = [1, 2, 4, 8]
            reglH = 0x40 | random_funcs.randel(arr7)
            # SUBPL rm, sp, #(c+24)
            output += dpimm(SUB, PL, 0, m, 13, c + 24)

            # Store 4 0x00
            # STRPLB random_funcs.randel(arr6), [!rm, -(r5 ROR #random_funcs.randel(arr5))]
            for _ in range(4):
                output += sbyteposti(random_funcs.randel(arr6), m, 5, random_funcs.randel(arr5))

            # Store 4 0xff
            # STRPLB r5, [!rm, -(r5 ROR #random_funcs.randel(arr5))]
            for _ in range(4):
                output += sbyteposti(5, m, 5, random_funcs.randel(arr5))

            # Store 4 0x00
            # STRPLB random_funcs.randel(arr6), [!rm, -(r5 ROR #random_funcs.randel(arr5))]
            for _ in range(4):
                output += sbyteposti(random_funcs.randel(arr6), m, 5, random_funcs.randel(arr5))

            # SUBPL rm, sp, #c
            output += dpimm(SUB, PL, 0, m, 13, c)

            # LDMPLDB rm!, {r0, r1, r2, r6, r8/9/10/11, r14}
            output += lmul(m, reglH, 0x47)

            # SUBPLS rm, r5, r4 ROR rm
            output += dpshiftreg(SUB, 1, m, 5, 4, ROR, m)

            self.size += 4 * 16
        return output

    def algo1(self, input, begin_inp, iter):
        if not input:
            return b''
        output = b''
        offset = 0x91

        def op(oper, arg):
            nonlocal output
            # (EORPLS|SUBPL|SBRPL). rk, ri, #arg
            output += dpimm(oper, PL, oper == EOR, self.k, self.i, arg)
            # STRPLB rk, [raddr, #(-offset)]
            output += lsbyte(STR, PL, self.k, self.addr, offset)
            # SUBPL raddr, raddr, rj ROR rk
            output += dpshiftreg(SUB, 0, self.addr, self.addr, self.j, ROR, self.k)

            self.size += 4 * 3

        for y in bytearray(input[begin_inp:begin_inp + iter]):
            if alphanum_byte.alphanumeric_check(y):
                # SUBPL raddr, raddr, rj ROR rk
                output += dpshiftreg(SUB, 0, self.addr, self.addr, self.j, ROR, self.k)
                self.size += 4
                continue
            if y >= 0x80:
                if alphanum_byte.alphanumeric_check(~y):
                    # EORPLS rk, rj, #~y
                    output += dpimm(EOR, PL, 1, self.k, self.j, ~y)
                    # STRMIB rk, [raddr, #(-offset)]
                    output += lsbyte(STR, MI, self.k, self.addr, offset)
                    # SUBMIS rk, ri, #x
                    output += dpimm(SUB, MI, 1, self.k, self.i, self.x)
                    # SUBPL raddr, raddr, rj ROR rk
                    output += dpshiftreg(SUB, 0, self.addr, self.addr, self.j, ROR, self.k)

                    self.size += 4 * 4
                    continue

                a = alphanum_byte.alphanumeric_get_complement(~y)
                b = (a ^ ~y) & 0xff
                # EORPLS rk, rj, #a
                output += dpimm(EOR, PL, 1, self.k, self.j, a)
                # EORMIS  rk,  rk, #b
                output += dpimm(EOR, MI, 1, self.k, self.k, b)
                # STRMIB rk, [raddr, #(-offset)]
                output += lsbyte(STR, MI, self.k, self.addr, offset)
                # SUBMIS rk, ri, #x
                output += dpimm(SUB, MI, 1, self.k, self.i, self.x)
                # SUBPL raddr, raddr, rj ROR rk
                output += dpshiftreg(SUB, 0, self.addr, self.addr, self.j, ROR, self.k)

                self.size += 4 * 5
                continue
            if self.x > y:
                z1 = self.x - y
                if alphanum_byte.alphanumeric_check(z1):
                    # SUBPL rk, ri, #z
                    op(SUB, z1)
                    continue
            z2 = self.x + y
            if alphanum_byte.alphanumeric_check(z2):
                # RSBPL rk, ri, #z
                op(RSB, z2)
                continue
            z3 = self.x ^ y
            if alphanum_byte.alphanumeric_check(z3):
                # EORPLS rk, ri, #z
                op(EOR, z3)
                continue
            a2 = alphanum_byte.alphanumeric_get_complement(z3)
            b2 = a2 ^ z3
            # EORPLS rk, rk, #a
            output += dpimm(EOR, PL, 1, self.k, self.k, a2)
            # EORPLS rk, ri, #b
            op(EOR, b2)
            self.size += 4
        return output

    def gap_traverse(self, gap):
        output = b''
        g = alphanum_byte.off_gen(gap)
        h = g + gap
        # SUBPL rj, ri, #x
        output += dpimm(SUB, PL, 0, self.j, self.i, self.x)
        # EORPLS rk, rj, #g
        output += dpimm(EOR, PL, 1, self.k, self.j, g)
        # SUBPL rk, rk, #h
        output += dpimm(SUB, PL, 0, self.k, self.k, h)
        # SUBPL raddr, raddr, rk LSR rj
        output += dpshiftreg(SUB, 0, self.addr, self.addr, self.k, LSR, self.j)
        # SUBPL rj, ri, #(x+1)
        output += dpimm(SUB, PL, 0, self.j, self.i, self.x + 1)

        self.size += 4 * 5
        return output

    def buildInit(self, input):
        if not input:
            return (b'', input)
        output = b''

        # Select values of v and w
        total = 0x70
        arr1 = [0x30, 0x34, 0x38]
        v1 = random_funcs.randel(arr1)
        v2 = random_funcs.randel(arr1)

        topv = ((total - (v1 + v2)) // 4) + 1

        w1 = random_funcs.randel(arr1)
        w2 = random_funcs.randel(arr1)

        topw = ((total - (w1 + w2)) // 4) + 2

        arrop = [EOR, SUB, RSB]
        arrcond = [PL, MI]
        arrs = [0, 1]
        arrd = [3, 5, 7]
        arrn = range(1, 10)
        p = 1
        while p <= ((total - 8) // 4):
            op = random_funcs.randel(arrop)
            cond = random_funcs.randel(arrcond)
            if op == EOR:
                s = 1
            else:
                s = random_funcs.randel(arrs)
            d = random_funcs.randel(arrd)
            n = random_funcs.randel(arrn)
            if p == topv or p == topw:
                output += dpimm(op, cond, s, d, n, self.x)
            else:
                output += dpimm(op, cond, s, d, n, alphanum_byte.alphanumeric_get_byte())
            p += 1

        # SUBPL ri, pc, #v1
        output += dpimm(SUB, PL, 0, self.i, 15, v1)
        # SUBMI ri, pc, #w1
        output += dpimm(SUB, MI, 0, self.i, 15, w1)
        # LDRPLB ri, [ri, #(-v2)]
        output += lsbyte(LDR, PL, self.i, self.i, v2)
        # LDRMIB ri, [ri, #(-w2)]
        output += lsbyte(LDR, MI, self.i, self.i, w2)

        output += self.algo2()

        # SUBPL rj, ri, #(x+1)
        output += dpimm(SUB, PL, 0, self.j, self.i, self.x + 1)
        # Initializer built!!

        # Replace 0x91s in decoder with addr_offset
        input_new = bytearray()
        for p in bytearray(input):
            if p == 0x91:
                input_new.append(self.addr_offset)
            else:
                input_new.append(p)
        return (output, bytes(input_new))

    def algo2(self):
        output = b''
        self.size += 4
        # SUBMIS rk, ri, #x
        output += dpimm(SUB, MI, 1, self.k, self.i, self.x)
        # SUBPLS rk, ri, #x
        output += dpimm(SUB, PL, 1, self.k, self.i, self.x)
        # SUBPL rj, ri, #x
        output += dpimm(SUB, PL, 0, self.j, self.i, self.x)

        quo, rem = divmod(self.size - 4, 0x7a)
        if quo >= 1:
            for p in range(quo):
                # SUBPL rj, rj, #0x7a
                output += dpimm(SUB, PL, 0, self.j, self.j, 0x7a)

        if rem >= 1 and rem <= 0x4a:
            self.addr_offset = alphanum_byte.off_gen(rem)
            # SUBPL rj, rj, #(offset+rem)
            output += dpimm(SUB, PL, 0, self.j, self.j, self.addr_offset + rem)

        if rem >= 0x4b and rem < 0x7a:
            if alphanum_byte.alphanumeric_check(rem):
                self.addr_offset = alphanum_byte.alphanumeric_get_byte()
                # SUBPL rj, rj, #(rem)
                output += dpimm(SUB, PL, 0, self.j, self.j, rem)
                # SUBPL rj, rj, #(offset)
                output += dpimm(SUB, PL, 0, self.j, self.j, self.addr_offset)
            else:
                self.addr_offset = alphanum_byte.off_gen(rem - 0x5a)
                # SUBPL rj, rj, #0x5a
                output += dpimm(SUB, PL, 0, self.j, self.j, 0x5a)
                # SUBPL rj, rj, #(offset + (rem - 0x5a))
                output += dpimm(SUB, PL, 0, self.j, self.j, self.addr_offset + rem - 0x5a)

        # SUBPL raddr, pc, rj ROR rk
        output += dpshiftreg(SUB, 0, self.addr, 15, self.j, ROR, self.k)
        return output
