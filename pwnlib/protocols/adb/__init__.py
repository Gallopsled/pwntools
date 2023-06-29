"""
Implementation of the Android Debug Bridge (ADB) protocol.

Documentation is available here_.

.. _here: https://android.googlesource.com/platform/system/core/+/master/adb/protocol.txt
"""
from __future__ import absolute_import
from __future__ import division

import logging
import functools
import six
import stat
import time

from pwnlib.context import context
from pwnlib.log import Logger
from pwnlib.log import getLogger
from pwnlib.tubes.listen import listen
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import remote
from pwnlib.util.lists import group
from pwnlib.util.misc import size
from pwnlib.util.packing import p32
from pwnlib.util.proc import pidof
from pwnlib.util.sh_string import sh_string

log = getLogger(__name__)

def pack(val):
    return '%04x' % val

def unpack(val):
    return int(val, 16)

OKAY = b"OKAY"
FAIL = b"FAIL"

class Message(object):
    """An ADB hex-length-prefixed message"""
    def __init__(self, string):
        self.string = string
    def __bytes__(self):
        return self.__flat__()
    def __str__(self):
        return self.__flat__()
    def __flat__(self):
        return b'%04x' % len(self.string) + self.string

class Connection(remote):
    """Connection to the ADB server"""
    def __init__(self, host, port, level=None, *a, **kw):
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
        self.send(bytes(Message(message)))
        return self.recvn(4)

    def adb_unpack(self):
        return unpack(self.recvn(4))

    def flat32(self, *a, **kw):
        kw.setdefault('word_size', 32)
        return super(Connection, self).flat(*a, **kw)

class Process(Connection):
    """Duck-typed ``tubes.remote`` object to add properties of a ``tubes.process``"""

class AdbClient(Logger):
    """ADB Client"""
    def __init__(self, level=None):
        super(AdbClient, self).__init__()

        if level is not None:
            self.setLevel(level)

        self.host = context.adb_host
        self.port = context.adb_port
        self._c   = None

    @property
    def c(self):
        """AdbClient's connection to the ADB server"""
        if not self._c:
            try:
                # Squelch the first '[ERROR] Could not connect to localhost on port 5037'
                level = self.level
                with context.quiet:
                    if not self.isEnabledFor(logging.INFO):
                        level = logging.FATAL
                    self._c = Connection(self.host, self.port, level=level)
            except Exception:
                # If the connection fails, try starting a server on that port
                # as long as it's the *default* port.
                if self.host == context.defaults['adb_host'] \
                and self.port == context.defaults['adb_port']:
                    log.warn("Could not connect to ADB server, trying to start it")
                    process(context.adb + ['start-server']).recvall()
                    time.sleep(0.3)
                else:
                    log.exception('Could not connect to ADB server (%s:%s)',
                                  self.host, self.port)

        # Final attempt...
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
        if isinstance(a[0], six.text_type):
            a = (a[0].encode('utf-8'),) + a[1:]
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
        """Kills the remote ADB server"
        
        .. doctest::
           :skipif: skip_android

            >>> c=pwnlib.protocols.adb.AdbClient()
            >>> c.kill()

        The server is automatically re-started on the next request,
        if the default host/port are used.

        .. doctest::
           :skipif: skip_android

            >>> c.version() > (4,0)
            True
            >>> c.wait_for_device() # ensure doctests alive
        """
        try:
            self.send('host:kill')
        except EOFError:
            pass

    @_autoclose
    def version(self):
        """
        Returns:
            Tuple containing the ``(major, minor)`` version from the ADB server

        Example:
        
        .. doctest::
           :skipif: skip_android

            >>> pwnlib.protocols.adb.AdbClient().version() # doctest: +SKIP
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
            long(bool): If :const:`True`, fetch the long-format listing.
        Returns:
            String representation of all available devices.
        """
        msg = 'host:devices'
        if long:
            msg += '-l'
        response = self.send(msg)
        if response == OKAY:
            l = self.recvl()
            if not hasattr(l, 'encode'):
                l = l.decode('utf-8')
            return l
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
            l = self.recvl()
            if not hasattr(l, 'encode'):
                l = l.decode('utf-8')
            yield l

    def transport(self, serial=None, try_again=True):
        """Sets the Transport on the remote device.

        Examples:

        .. doctest::
           :skipif: skip_android

            >>> pwnlib.protocols.adb.AdbClient().transport()
        """

        # If no serial was explicitly provided, try the current device
        if not serial and context.device:
            serial = context.device

        # Select the appropriate (or any) device
        if serial:
            # Extract the serial, str(Device) --> serial
            serial = str(serial)
            msg = 'host:transport:%s' % serial
        else:
            msg = 'host:transport-any'

        if self.send(msg) == FAIL:
            err = self.recvl().decode('utf-8')
            if err == 'device offline' and try_again:
                self.wait_for_device(serial)
                return self.transport(serial, try_again=False)
            if serial:
                self.error("Could not set transport to %r (%s)" % (serial, err))
            else:
                self.error("Could not set transport 'any' (%s)" % err)

    @_autoclose
    @_with_transport
    def execute(self, argv):
        r"""Executes a program on the device.

        Returns:
            A :class:`pwnlib.tubes.tube.tube` which is connected to the process.

        Examples:

        .. doctest::
           :skipif: skip_android

            >>> pwnlib.protocols.adb.AdbClient().execute(['echo','hello']).recvall()
            b'hello\n'
        """
        self.transport(context.device)
        if isinstance(argv, str):
            argv = [argv]
        cmd = 'exec:%s' % (' '.join(map(sh_string, argv)))
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
        rv = self.c.recvall().decode('utf-8')
        time.sleep(0.1)
        return rv

    @_autoclose
    @_with_transport
    def unroot(self):
        self.send('unroot:')
        return self.c.recvall().decode('utf-8')

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
        if serial:
            response = self.send('host-serial:%s:wait-for-any-device' % serial)
        else:
            response = self.send('host:wait-for-any-device')

        # The first OKAY is that the command was understood
        if response != OKAY:
            if response == FAIL:
                response = self.recvl().decode('utf-8')
            self.error("An error occurred while trying to wait for device with serial %r (%r)" % (serial, response))

        # The second OKAY is that the device is available
        response = self.c.recvn(4)
        if response != OKAY:
            if response == FAIL:
                response = self.recvl().decode('utf-8')
            self.error("An error occurred while waiting for device with serial %r (%r)" % (serial, response))

    def _sync(fn):
        """Decorator which enters 'sync:' mode to the selected transport,
        then invokes the decorated funciton."""
        @functools.wraps(fn)
        def wrapper(self, *a, **kw):
            if self.send('sync:') == FAIL:
                self.error("An error occurred while trying to use SYNC API (%r)" % self.recvl().decode('utf-8'))
            return fn(self, *a, **kw)
        return wrapper

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
        
        .. doctest::
           :skipif: skip_android

            >>> _ = AdbClient().root()
            >>> AdbClient().wait_for_device()
            >>> pprint(AdbClient().list('/data/user'))
            {'0': {'mode': 41471, 'size': 10, 'time': ...}}
            >>> AdbClient().list('/does/not/exist')
            Traceback (most recent call last):
            ...
            PwnlibException: Cannot list directory '/does/not/exist': Does not exist
        """
        st = self.stat(path)

        if not st:
            log.error("Cannot list directory %r: Does not exist" % path)

        if not stat.S_ISDIR(st['mode']):
            log.error("Cannot list directory %r: Path is not a directory" % path)

        return self._list(path)

    @_with_transport
    @_sync
    def _list(self, path):
        if isinstance(path, six.text_type):
            path = path.encode('utf-8')
        self.c.flat32(b'LIST', len(path), path)
        files = {}
        while True:
            response = self.c.recvn(4)

            if response == b'DONE':
                break

            if response != b'DENT':
                self.error('Unexpected response: %r' % response)

            mode = self.c.u32()
            size = self.c.u32()
            time = self.c.u32()
            name = self.c.recvn(self.c.u32())

            if not hasattr(name, 'encode'):
                name = name.decode('utf-8')

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
        """Execute the STAT command of the SYNC API.

        Arguments:
            path(str): Path to the file to stat.

        Return:
            On success, a dictionary mapping the values returned.
            If the file cannot be stat() ed, None is returned.

        Example:
        
        .. doctest::
           :skipif: skip_android

            >>> expected = {'mode': 16749, 'size': 0, 'time': 0}
            >>> pwnlib.protocols.adb.AdbClient().stat('/proc')           == expected
            True
            >>> pwnlib.protocols.adb.AdbClient().stat('/does/not/exist') is None
            True
        """
        if isinstance(path, six.text_type):
            path = path.encode('utf-8')
        self.c.flat32(b'STAT', len(path), path)
        if self.c.recvn(4) != b'STAT':
            self.error("An error occurred while attempting to STAT a file.")

        mode = self.c.u32()
        size = self.c.u32()
        time = self.c.u32()

        if (mode,size,time) == (0,0,0):
            return None

        return {'mode': mode, 'size': size, 'time': time}

    def write(self, path, data, mode=0o755, timestamp=None, callback=None):
        """Execute the ``WRITE`` command of the ``SYNC`` API.

        Arguments:
            path(str): Path to the file to write
            data(str): Data to write to the file
            mode(int): File mode to set (e.g. ``0o755``)
            timestamp(int): Unix timestamp to set the file date to
            callback(callable): Callback function invoked as data
                is written.  Arguments provided are:

                - File path
                - All data
                - Expected size of all data
                - Current chunk
                - Expected size of chunk
        """
        # We must ensure that 'path' is not a directory
        # Writing to a directory is supported, but creates a temporary file
        st = self.stat(path)

        if st and stat.S_ISDIR(st['mode']):
            log.error("Cannot write to %r: Path is a directory" % path)

        return self._write(path, data, mode=0o755, timestamp=None, callback=None)

    @_with_transport
    @_sync
    def _write(self, path, data, mode=0o755, timestamp=None, callback=None):
        if isinstance(path, six.text_type):
            path = path.encode('utf-8')
        path += b',%d' % mode

        self.c.flat32(b'SEND', len(path), path)

        sent = 0

        # Data needs to be broken up into chunks!
        for chunk in group(0x10000, data):
            self.c.flat32(b'DATA', len(chunk), chunk)
            if callback:
                callback(path, data[:sent], len(data), chunk, len(chunk))
            sent += len(chunk)

        # Send completion notification and timestamp
        if timestamp is None:
            timestamp = int(time.time())
        self.c.flat32(b'DONE', timestamp)

        result = self.c.recvn(4)
        if result != OKAY:
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
        if isinstance(path, six.text_type):
            path = path.encode('utf-8')
        self.c.send(b'RECV' + p32(len(path)) + path)

        # Accumulate all data here
        all_data = b''

        while True:
            magic = self.c.recvn(4)

            # adbd says there is no more data to send
            if magic == b'DONE':
                break

            if magic == FAIL:
                self.error('Could not read file %r: Got FAIL.' % path)

            # did we expect to be done?
            if magic != b'DATA':
                self.error('Error after file read: %r (expected DATA)' % magic)

            # receive all of the data in the chunk
            chunk_size = self.c.u32()
            chunk_data  = b''
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
    l.connect_both(r)
