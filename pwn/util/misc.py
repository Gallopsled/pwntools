import struct
from socket import htons, inet_aton, inet_ntoa, gethostbyname
from os import system
from time import sleep

def p8(x):
    return struct.pack('<B', x & 0xff)

def p8b(x):
    return struct.pack('>B', x & 0xff)

def p16(x):
    return struct.pack('<H', x & 0xffff)

def p16b(x):
    return struct.pack('>H', x & 0xffff)

def p32(x):
    return struct.pack('<I', x & 0xffffffff)

def p32b(x):
    return struct.pack('>I', x & 0xffffffff)

def p64(x):
    return struct.pack('<Q', x & 0xffffffffffffffff)

def p64b(x):
    return struct.pack('>Q', x & 0xffffffffffffffff)

def dehex(s):
    return s.decode('hex')

def enhex(s):
    return s.encode('hex')

def ip (host):
    return struct.unpack('I', inet_aton(gethostbyname(host)))[0]
