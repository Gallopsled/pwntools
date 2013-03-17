import pwn
import zlib

def huffman_chop(data, dic):
    data = ''.join(str(int(d)) for d in data)
    for n,v in dic.items():
        if data.startswith(n):
            return v, data[len(n):]
    return None

def huffman_generate(counts):

    if isinstance(counts[0], int):
        counts = zip(counts, range(len(counts)))

    lens = pwn.partition(counts, lambda x: x[0], True)

    res = {}

    n = 0
    last = 0

    for l,vs in sorted(lens.items()):
        if l == 0:
            continue
        n = n << (l - last)
        last = l
        for _l,v in vs:
            res[bin(n)[2:].rjust(l, "0")] = v
            n += 1
    return res

def u_little(s):
    return int('0' + s[::-1], 2)

def u_big(s):
    return int('0' + s, 2)

def chop_little(s, n):
    return u_little(s[:n]), s[n:]

def chop_big(s, n):
    return u_big(s[:n]), s[n:]

#s = pwn.bits_str(zlib.compress(pwn.randoms(10, only='abcdef') * 1000, 9)[2:-4], endian='little')
s = pwn.bits_str(zlib.compress('foobar' * 1000, 9)[2:-4], endian='little')
s = pwn.bits_str(pwn.b64d('8pFHHoMssjtoucpX4EdPgcrdzuKXgEFV7iNur4YzDrOdfyNOA/bp7lX='), endian='little')

is_end,   s = chop_little(s, 1)
enc_type, s = chop_little(s, 2)

print is_end, enc_type

if enc_type != 0b10:
    pwn.die("type was not dynamic huffman")

hlit,  s = chop_little(s, 5)
hdist, s = chop_little(s, 5)
hclen, s = chop_little(s, 4)

hlit += 257
hdist += 1
hclen += 4

lens = []

for n in range(hclen):
    c, s = chop_little(s, 3)
    lens.append(c)

lens = sorted(zip(lens, [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]))
code_dict = huffman_generate(lens)

out = []
while len(out) < hlit + hdist:
    c, s = huffman_chop(s, code_dict)
    if c <= 15:
        out += [c]
    elif c == 16:
        l, s = chop_little(s, 2)
        out += out[-1:] * (l+3)
    elif c == 17:
        l, s = chop_little(s, 3)
        out += [0] * (l+3)
    elif c == 18:
        l, s = chop_little(s, 7)
        out += [0] * (l+11)
    else:
        pwn.die("something went wrong while parsing the code table1")

if len(out) != hlit + hdist:
    pwn.die("something went wrong while parsing the code table2")

lit_dict  = huffman_generate(out[:hlit])
dist_dict = huffman_generate(out[hlit:])

print lit_dict, dist_dict

out = []

while True:
    lit_code, s = huffman_chop(s, lit_dict)

    if lit_code < 256:
        out += [lit_code]
        continue
    elif lit_code == 256:
        break
    elif lit_code < 261:
        repeat_len = lit_code - 275 + 3
    elif lit_code < 285:
        extra_bits = (lit_code - 261) // 4
        extra, s = chop_big(s, extra_bits)
        # TODO: This is damn ugly
        repeat_len = 7 + sum(2**(n//4) for n in range(lit_code-261)) + extra
    elif lit_code == 285:
        repeat_len = 258
    else:
        pwn.die("Invalid lit code")

    dist_code, s = huffman_chop(s, dist_dict)

    if dist_code < 2:
        dist = dist_code + 1
    elif dist_code < 30:
        extra_bits = (dist_code - 2) // 2
        extra, s = chop_big(s, extra_bits)
        dist = 3 + sum(2**(n//2) for n in range(dist_code-2)) + extra
    else:
        pwn.die("Invalid dist code")

    for n in range(repeat_len):
        out += [out[-dist]]

print len(pwn.unordlist(out))
print pwn.unordlist(out)
#print pwn.unordlist(out)

#d = huffman_generate([2,2,2,3,3], [1,3,18,0,2])
