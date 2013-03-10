#!/usr/bin/env python

import rpyc
from rpyc.utils.registry import TCPRegistryClient

class CloudService(rpyc.Service):
    def on_connect(self):
        print "Incoming connection"
        pass

    def on_disconnect(self):
        print "Closing connection"
        pass

    def exposed_doit(self, code):
        '''Execute arbitrary python code, given as a string, and returns the namespace in which it was executed.
'''
        cloud = {}
        try:
            exec(code) in cloud
        except:
            pass
        return cloud


if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    import logging
    import socket
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger('CloudServer')
    hostname = socket.gethostbyname(socket.gethostname())
    t = ThreadedServer(CloudService, hostname=hostname, port = 31337, registrar = TCPRegistryClient(hostname), logger = log)
    t.start()
