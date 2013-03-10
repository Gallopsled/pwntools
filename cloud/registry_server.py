#!/usr/bin/env python
"""
The registry server listens to broadcasts on UDP port 18812, answering to
discovery queries by clients and registering keepalives from all running
servers. In order for clients to use discovery, a registry service must
be running somewhere on their local network.
"""
from optparse import OptionParser
from rpyc.utils.registry import REGISTRY_PORT, DEFAULT_PRUNING_TIMEOUT
from rpyc.utils.registry import UDPRegistryServer, TCPRegistryServer
from rpyc.lib import setup_logger


parser = OptionParser()
parser.add_option("-m", "--mode", action="store", dest="mode", metavar="MODE",
    default="udp", type="string", help="mode can be 'udp' or 'tcp'")
parser.add_option("-p", "--port", action="store", dest="port", type="int",
    metavar="PORT", default=REGISTRY_PORT, help="specify a different UDP/TCP listener port")
parser.add_option("-f", "--file", action="store", dest="logfile", type="str",
    metavar="FILE", default=None, help="specify the log file to use; the default is stderr")
parser.add_option("-q", "--quiet", action="store_true", dest="quiet",
    default=False, help="quiet mode (only errors are logged)")
parser.add_option("-t", "--timeout", action="store", dest="pruning_timeout",
    type="int", default=DEFAULT_PRUNING_TIMEOUT, help="sets a custom pruning timeout")

def main():
    options, args = parser.parse_args()
    if args:
        raise ValueError("does not take positional arguments: %r" % (args,))

    if options.port < 1 or options.port > 65535:
        raise ValueError("invalid TCP/UDP port %r" % (options.port,))

    if options.mode.lower() == "udp":
        server = UDPRegistryServer(port = options.port,
            pruning_timeout = options.pruning_timeout)
    elif options.mode.lower() == "tcp":
        server = TCPRegistryServer(port = options.port,
            pruning_timeout = options.pruning_timeout)
    else:
        raise ValueError("invalid mode %r" % (options.mode,))

    setup_logger(options)
    server.start()


if __name__ == "__main__":
    main()
