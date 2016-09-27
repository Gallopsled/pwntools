"""
Implementation of the Android Debug Bridge (ADB) protocol, as far as Binjitsu needs it.

Documentation is available here:
https://android.googlesource.com/platform/system/core/+/master/adb/protocol.txt
"""
import functools
import time

from ..context import context
from ..log import Logger
from ..log import getLogger
from ..tubes.listen import listen
from ..tubes.process import process
from ..tubes.remote import remote
from ..util.lists import group
from ..util.misc import size
from ..util.packing import p32
from ..util.proc import pidof
from ..util.sh_string import sh_string

log = getLogger(__name__)

def pack(val):
    return '%04x' % val

def unpack(val):
    return int(val, 16)

OKAY = "OKAY"
FAIL = "FAIL"

class Message(object):
    """An ADB hex-length-prefixed message"""
    def __init__(self, string):
        self.string = string
    def __str__(self):
        return ('%04x' % len(self.string)) + self.string
    def __flat__(self):
        return str(self)

class Connection(remote):
    """Connection to the ADB server"""
    def __init__(self, host, port, level=None, *a, **kw):

        # Try to make sure ADB is running if it's on the default host and port.
        if host == context.defaults['adb_host'] \
        and port == context.defaults['adb_port']:
            process(context.adb + ['start-server'], level='error').wait_for_close()

        with context.quiet:
            super(Connection, self).__init__(host, port, level=level, *a, **kw)

        self._executable = None
        self._argv       = None
        self._pid        = None
        self._cwd        = None
        self._env        = None

    def close(self):
        with context.quiet:
            super(Connection, self).close()

    def adb_send(self, message):
        self.send(str(Message(message)))
        return self.recvn(4)

    def adb_unpack(self):
        return unpack(self.recvn(4))

    def flat(self, *a, **kw):
        kw.setdefault('word_size', 32)
        return super(Connection, self).flat(*a, **kw)

class Process(Connection):
    """Duck-typed ``tubes.remote`` object to add properties of a ``tubes.process``"""

class Client(Logger):
    """ADB Client"""
    def __init__(self, level=None):
        super(Client, self).__init__()

        if level is not None:
            self.setLevel(level)

        self.host = context.adb_host
        self.port = context.adb_port
        self._c   = None

    @property
    def c(self):
        """Client's connection to the ADB server"""
        if not self._c:
            self._c = Connection(self.host, self.port, level=self.level)
        return self._c

    def _autoclose(fn):
        """Decorator which automatically closes the connection to the ADB server
        after calling the decorated function."""
        @functools.wraps(fn)
        def wrapper(self, *a, **kw):
            rv = fn(self, *a, **kw)
            if self._c:
                self._c.close()
                self._c = None
            return rv
        return wrapper

    def _with_transport(fn):
        """Decorator which automatically selects a device transport before calling
        the decorated function, and closes the connection afterward."""
        @functools.wraps(fn)
        def wrapper(self, *a, **kw):
            self.transport()
            rv = fn(self, *a, **kw)
            if self._c:
                self._c.close()
                self._c = None
            return rv
        return wrapper

    def send(self, *a, **kw):
        """Sends data to the ADB server"""
        return self.c.adb_send(*a, **kw)

    def unpack(self, *a, **kw):
        """Receives a hex-ascii packed integer from the ADB server"""
        return self.c.adb_unpack(*a, **kw)

    def recvl(self):
        """Receives a length-prefixed data buffer from the ADB server"""
        length = self.c.adb_unpack()
        return self.c.recvn(length)

    @_autoclose
    def kill(self):
        """Kills the remote ADB server"""
        try:
            self.send('host:kill')
        except EOFError:
            pass

    def version(self):
        """
        Returns:
            Tuple containing the ``(major, minor)`` version from the ADB server

        Example:

            >>> adb.protocol.Client().version() # doctest: +SKIP
            (4, 36)
        """
        response = self.send('host:version')
        if response == OKAY:
            return (self.c.adb_unpack(), self.c.adb_unpack())
        self.error("Could not fetch version")

    @_autoclose
    def devices(self, long=False):
        """
        Arguments:
            long(bool): If ``True``, fetch the long-format listing.
        Returns:
            String representation of all available devices.
        """
        msg = 'host:devices'
        if long:
            msg += '-l'
        response = self.send(msg)
        if response == 'OKAY':
            return self.recvl()
        self.error("Could not enumerate devices")

    @_autoclose
    def track_devices(self):
        """
        Returns:
            Generator which returns a short-format listing of available
            devices each time a device state changes.
        """
        self.send('host:track-devices')
        while True:
            yield self.recvl()

    def transport(self, serial=None):
        """Sets the Transport on the rmeote device.

        Examples:

            >>> adb.protocol.Client().transport()
        """
        msg = 'host:transport:%s' % (serial or context.device)
        if self.send(msg) == FAIL:
            self.error("Could not set transport to %r" % serial)

    @_autoclose
    @_with_transport
    def execute(self, argv):
        r"""Executes a program on the device.

        Returns:
            A ``tube`` which is connected to the process.

        Examples:

            >>> adb.protocol.Client().execute(['echo','hello']).recvall()
            'hello\n'
        """
        self.transport(context.device)
        if isinstance(argv, str):
            argv = [argv]
        argv = list(map(sh_string, argv))
        cmd = 'exec:%s' % (' '.join(argv))
        if OKAY == self.send(cmd):
            rv = self._c
            self._c = None
            return rv

    def _basic_wrapper(string):
        @_autoclose
        @_with_transport
        def wrapper(self):
            self.send(string)
            return self.c.recvall()
        return wrapper

    @_autoclose
    @_with_transport
    def remount(self):
        self.send('remount:')
        return self.c.recvall()

    @_autoclose
    @_with_transport
    def root(self):
        self.send('root:')
        return self.c.recvall()

    @_autoclose
    @_with_transport
    def unroot(self):
        self.send('unroot:')
        return self.c.recvall()

    @_autoclose
    @_with_transport
    def disable_verity(self):
        self.send('disable-verity:')
        return self.c.recvall()

    @_autoclose
    @_with_transport
    def enable_verity(self):
        self.send('enable-verity:')
        return self.c.recvall()

    @_autoclose
    @_with_transport
    def reconnect(self):
        self.send('reconnect:')
        return self.c.recvall()

    @_autoclose
    @_with_transport
    def reboot(self):
        self.send('reboot:')
        return self.c.recvall()

    @_autoclose
    @_with_transport
    def reboot_bootloader(self):
        self.send('reboot:bootloader')
        return self.c.recvall()

    @_autoclose
    def wait_for_device(self, serial=''):
        response = self.send('host-serial:%s:wait-for-any-device' % serial)

        # The first OKAY is that the command was understood
        if response != 'OKAY':
            self.error("An error occurred while waiting for device with serial %r" % serial)

        # The second OKAY is that the device is available
        response = self.c.recvn(4)
        if response != 'OKAY':
            self.error("An error occurred while waiting for device with serial %r" % serial)

    def _sync(fn):
        """Decorator which enters 'sync:' mode to the selected transport,
        then invokes the decorated funciton."""
        @functools.wraps(fn)
        def wrapper(self, *a, **kw):
            rv = None
            if FAIL != self.send('sync:'):
                rv = fn(self, *a, **kw)
            return rv
        return wrapper

    @_with_transport
    @_sync
    def list(self, path):
        """Execute the ``LIST`` command of the ``SYNC`` API.

        Arguments:
            path(str): Path of the directory to list.

        Return:
            A dictionary, where the keys are relative filenames,
            and the values are a dictionary containing the same
            values as ``stat()`` supplies.

        Note:
            In recent releases of Android (e.g. 7.0), the domain that
            adbd executes from does not have access to everything that
            the shell user does.

            Because of this, while the shell user can get listings of
            e.g. the root directory ('/'), adbd cannot.

            The SYNC APIs are executed within the adbd context, not the
            shell user context.

            This issue is not a problem if the phone is rooted via
            'adb root', since adbd then runs in the ``su`` domain.

        Examples:

            >>> pprint(adb.Client().list('/data/user'))
            {'0': {'mode': 41471, 'size': 11, 'time': ...}}
            >>> adb.Client().list('/does/not/exist')
            {}
        """
        self.c.flat('LIST', len(path), path)
        files = {}
        while True:
            response = self.c.recvn(4)

            if response == 'DONE':
                break

            if response != 'DENT':
                self.error('Unexpected response: %r' % response)

            mode = self.c.u32()
            size = self.c.u32()
            time = self.c.u32()
            name = self.c.recvn(self.c.u32())

            # Ignore the current directory and parent
            if name in ('', '.', '..'):
                continue

            files[name] = {'mode': mode,
                           'size': size,
                           'time': time}

        return files

    @_with_transport
    @_sync
    def stat(self, path):
        """Execute the ``STAT`` command of the ``SYNC`` API.

        Arguments:
            path(str): Path to the file to stat.

        Return:
            On success, a dictionary mapping the values returned.
            If the file cannot be ``stat()``ed, None is returned.

        Example:

            >>> expected = {'mode': 16749, 'size': 0, 'time': 0}
            >>> adb.protocol.Client().stat('/proc')           == expected
            True
            >>> adb.protocol.Client().stat('/does/not/exist') == None
            True
        """
        self.c.flat('STAT', len(path), path)
        if self.c.recvn(4) != 'STAT':
            self.error("An error occured while attempting to STAT a file.")

        mode = self.c.u32()
        size = self.c.u32()
        time = self.c.u32()

        if (mode,size,time) == (0,0,0):
            return None

        return {'mode': mode, 'size': size, 'time': time}

    @_with_transport
    @_sync
    def write(self, path, data, mode=0o755, timestamp=None, callback=None):
        path += ',' + str(mode)
        self.c.flat('SEND', len(path), path)

        sent = 0

        # Data needs to be broken up into chunks!
        for chunk in group(0x10000, data):
            self.c.flat('DATA', len(chunk), chunk)
            if callback:
                callback(path, data[:sent], len(data), chunk, len(chunk))
            sent += len(chunk)

        # Send completion notification and timestamp
        if timestamp is None:
            timestamp = int(time.time())
        self.c.flat('DONE', timestamp)

        result = self.c.recvn(4)
        if result != 'OKAY':
            log.error("Sync write failed: %r (expected OKAY)" % result)

        return

    @_with_transport
    @_sync
    def read(self, path, filesize=0, callback=lambda *a: True):
        """Execute the ``READ`` command of the ``SYNC`` API.

        Arguments:
            path(str): Path to the file to read
            filesize(int): Size of the file, in bytes.  Optional.
            callback(callable): Callback function invoked as data
                becomes available.  Arguments provided are:

                - File path
                - All data
                - Expected size of all data
                - Current chunk
                - Expected size of chunk

        Return:
            The data received as a string.
        """
        self.c.send('RECV' + p32(len(path)) + path)

        # Accumulate all data here
        all_data = ''

        while True:
            magic = self.c.recvn(4)

            # adbd says there is no more data to send
            if magic == 'DONE':
                break

            if magic == 'FAIL':
                self.error('Could not read file %r: Got FAIL.' % path)

            # did we expect to be done?
            if magic != 'DATA':
                self.error('Error after file read: %r (expected DATA)' % magic)

            # receive all of the data in the chunk
            chunk_size = self.c.u32()
            chunk_data  = ''
            while len(chunk_data) != chunk_size:
                chunk_data += self.c.recv(chunk_size - len(chunk_data))

                if callback:
                    callback(path,
                             all_data,
                             filesize,
                             chunk_data,
                             chunk_size)

            # add the chunk onto what we have
            all_data += chunk_data

        zero = self.c.u32()
        if zero != 0:
            self.error('Error after file read: %r (expected ZERO)' % zero)

        return all_data

    @_with_transport
    def forward(self, device, host_proto, host_port, device_proto, device_port):
        self.send('host:forward:%s:%s;%s:%s' % (host_proto, host_port, device_proto, device_port))
        self.c.recvall()

    def __enter__(self, *a, **kw):
        return self

    @_autoclose
    def __exit__(self, *a, **kw): pass

def proxy(port=9999):
    """Starts an ADB proxy on the specified port, for debugging purposes."""
    l = listen(port)
    l.wait_for_connection()
    r = remote(context.adb_host, context.adb_port, level='debug')
    l <> r
