from pwn import *
import rpyc
from rpyc.utils.registry import TCPRegistryClient
import socket

def cloud(code):
    hostname = socket.gethostbyname(socket.gethostname())
    hostinfo, _ = rpyc.discover('CLOUD', registrar = TCPRegistryClient(hostname))
    ip, port = hostinfo
    c = rpyc.connect(ip, port)
    return c.root.doit(code)

