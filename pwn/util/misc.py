# top-level imports
import struct
from socket import htons, inet_aton, inet_ntoa, gethostbyname
from os import system
from time import sleep

# conversion functions
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

def u8(x):
    return struct.unpack('<B', x)[0]

def u8b(x):
    return struct.unpack('>B', x)[0]

def u16(x):
    return struct.unpack('<H', x)[0]

def u16b(x):
    return struct.unpack('>H', x)[0]

def u32(x):
    return struct.unpack('<I', x)[0]

def u32b(x):
    return struct.unpack('>I', x)[0]

def u64(x):
    return struct.unpack('<Q', x)[0]

def u64b(x):
    return struct.unpack('>Q', x)[0]

def dehex(s):
    return s.decode('hex')

def enhex(s):
    return s.encode('hex')

# network utils
def ip (host):
    return struct.unpack('I', inet_aton(gethostbyname(host)))[0]
