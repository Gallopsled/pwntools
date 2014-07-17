import basechatter
import socket

class Remote(basechatter.basechatter, socket.socket):
    def __init__(self, addr, port):
        socket.socket.__init__(self)
        self.connect((addr, port))
