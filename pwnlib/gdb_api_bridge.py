"""GDB Python API bridge."""
import gdb

import socket
from threading import Condition
import time

from rpyc.core.protocol import Connection
from rpyc.core.service import Service
from rpyc.lib import spawn
from rpyc.lib.compat import select_error
from rpyc.utils.server import ThreadedServer


class ServeResult:
    """Result of serving requests on GDB thread."""
    def __init__(self):
        self.cv = Condition()
        self.done = False
        self.exc = None

    def set(self, exc):
        with self.cv:
            self.done = True
            self.exc = exc
            self.cv.notify()

    def wait(self):
        with self.cv:
            while not self.done:
                self.cv.wait()
            if self.exc is not None:
                raise self.exc


class GdbConnection(Connection):
    """A Connection implementation that serves requests on GDB thread.

    Serving on GDB thread might not be ideal from the responsiveness
    perspective, however, it is simple and reliable.
    """
    SERVE_TIME = 0.1  # Number of seconds to serve.
    IDLE_TIME = 0.1  # Number of seconds to wait after serving.

    def serve_gdb_thread(self, serve_result):
        """Serve requests on GDB thread."""
        try:
            deadline = time.time() + self.SERVE_TIME
            while True:
                timeout = deadline - time.time()
                if timeout < 0:
                    break
                super().serve(timeout=timeout)
        except Exception as exc:
            serve_result.set(exc)
        else:
            serve_result.set(None)

    def serve_all(self):
        """Modified version of rpyc.core.protocol.Connection.serve_all."""
        try:
            while not self.closed:
                serve_result = ServeResult()
                gdb.post_event(lambda: self.serve_gdb_thread(serve_result))
                serve_result.wait()
                time.sleep(self.IDLE_TIME)
        except (socket.error, select_error, IOError):
            if not self.closed:
                raise
        except EOFError:
            pass
        finally:
            self.close()


class GdbService(Service):
    """A public interface for Pwntools."""

    _protocol = GdbConnection  # Connection subclass.
    exposed_gdb = gdb  # ``gdb`` module.

    def exposed_set_breakpoint(self, client, has_stop, *args, **kwargs):
        """Create a breakpoint and connect it with the client-side mirror."""
        if has_stop:
            class Breakpoint(gdb.Breakpoint):
                def stop(self):
                    return client.stop()

            return Breakpoint(*args, **kwargs)
        return gdb.Breakpoint(*args, **kwargs)

    def exposed_quit(self):
        """Terminate GDB."""
        gdb.post_event(lambda: gdb.execute('quit'))


spawn(ThreadedServer(
    service=GdbService(),
    socket_path=socket_path,
    protocol_config={
        'allow_all_attrs': True,
    },
).start)
