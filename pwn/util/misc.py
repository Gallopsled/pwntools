import struct
from socket import htons, inet_aton, inet_ntoa, gethostbyname

def p(a):
    return struct.pack('I', a & 0xffffffff)

def dehex(s):
    return s.decode('hex')

def enhex(s):
    return s.encode('hex')

def ip (host):
    return struct.unpack('I', inet_aton(gethostbyname(host)))[0]
