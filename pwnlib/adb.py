"""Provides utilities for interacting with Android devices via the Android Debug Bridge.
"""
import os
import re
import tempfile

import dateutil.parser

from . import atexit
from . import tubes
from .context import context
from .context import LocalContext
from .log import getLogger
from .util import misc

log = getLogger(__name__)

def adb(argv, *a, **kw):
    """Returns the output of an ADB subcommand."""
    if isinstance(argv, (str, unicode)):
        argv = [argv]

    log.debug("$ " + ' '.join(['adb'] + argv))

    if context.device:
        argv = ['-s', context.device] + argv

    return tubes.process.process(context.adb + argv, *a, **kw).recvall()

def root():
    """Restarts adbd as root."""
    log.info("Enabling root on %s" % context.device)

    with context.quiet:
        reply  = adb('root')

    if 'already running as root' in reply:
        return

    elif not reply or 'restarting adbd as root' in reply:
        with context.quiet:
            wait_for_device()

    else:
        log.error("Could not run as root:\n%s" % reply)


def reboot(wait=True):
    """Reboots the device."""
    log.info('Rebooting device %s' % context.device)

    with context.quiet:
        adb('reboot')

    if wait:
        wait_for_device()

def reboot_bootloader():
    """Reboots the device to the bootloader."""
    log.info('Rebooting %s to bootloader' % context.device)

    with context.quiet:
        adb('reboot-bootloader')

class Device(object):
    """Encapsulates information about a connected device."""
    def __init__(self, serial, type, port, product, model, device):
        self.serial  = serial
        self.type    = type
        self.port    = port
        self.product = product
        self.model   = model.replace('_', ' ')
        self.device  = device

    def __str__(self):
        return self.serial

    def __repr__(self):
        fields = ['serial', 'type', 'port', 'product', 'model', 'device']
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(('%s=%r' % (field, getattr(self, field)) for field in fields)))

    @staticmethod
    def from_adb_output(line):
        fields = line.split()

        """
        Example output:
        ZX1G22LM7G             device usb:336789504X product:shamu model:Nexus_6 device:shamu features:cmd,shell_v2
        84B5T15A29020449       device usb:336855040X product:angler model:Nexus_6P device:angler
        """

        # The last few fields need to be split at colons.
        split  = lambda x: x.split(':')[-1]
        fields[3:] = list(map(split, fields[3:]))

        return Device(*fields[:6])

    def __getattr__(self, attr):
        module = self.__module__
        if hasattr(module, attr):
            with context.local(device=self.serial):
                return getattr(module, attr)
        return super(Device, self).__getattr__(attr)

@context.quiet
def devices(serial=None):
    """Returns a list of ``Device`` objects corresponding to the connected devices."""
    lines = adb(['devices', '-l'])
    result = []

    for line in lines.splitlines():
        # Skip the first 'List of devices attached' line, and the final empty line.
        if 'List of devices' in line or not line.strip():
            continue
        device = Device.from_adb_output(line)
        if device.serial == serial:
            return device
        result.append(device)

    return tuple(result)

@LocalContext
def wait_for_device():
    """Waits for a device to be connected."""
    with log.waitfor("Waiting for device to come online") as w:
        with context.quiet:
            adb('wait-for-device')

        if context.device:
            return context.device

        for device in devices():
            break
        else:
            log.error("Could not find any devices")

        with context.local(device=device):
            # There may be multiple devices, so context.device is
            # insufficient.  Pick the first device reported.
            w.success('%s (%s %s %s)' % (device,
                                         product(),
                                         build(),
                                         _build_date()))

    return device

def disable_verity():
    """Disables dm-verity on the device."""
    with log.waitfor("Disabling dm-verity on %s" % context.device) as w:
        root()

        with context.quiet:
            reply = adb('disable-verity')

        if 'Verity already disabled' in reply:
            return
        elif 'Now reboot your device' in reply:
            reboot(wait=True)
        else:
            log.error("Could not disable verity:\n%s" % reply)


def remount():
    """Remounts the filesystem as writable."""
    with log.waitfor("Remounting filesystem on %s" % context.device) as w:
        disable_verity()
        root()

        with context.quiet:
            reply = adb('remount')

        if 'remount succeeded' not in reply:
            log.error("Could not remount filesystem:\n%s" % reply)

def unroot():
    """Restarts adbd as AID_SHELL."""
    log.info("Unrooting %s" % context.device)
    with context.quiet:
        reply  = adb('unroot')

    if 'restarting adbd as non root' not in reply:
        log.error("Could not run as root:\n%s" % reply)

def pull(remote_path, local_path=None):
    """Download a file from the device.

    Arguments:
        remote_path(str): Path or directory of the file on the device.
        local_path(str): Path to save the file to.
            Uses the file's name by default.
    """
    if local_path is None:
        local_path = os.path.basename(remote_path)

    msg = "Pulling %r from %r" % (remote_path, local_path)

    if context.log_level == 'debug':
        msg += ' (%s)' % context.device

    with log.waitfor(msg) as w:
        with context.quiet:
            reply = adb(['pull', remote_path, local_path])

        if ' bytes in ' not in reply:
            log.error(reply)

def push(local_path, remote_path):
    """Upload a file to the device.

    Arguments:
        local_path(str): Path to the local file to push.
        remote_path(str): Path or directory to store the file on the device.
    """
    msg = "Pushing %r to %r" % (local_path, remote_path)

    if context.log_level == 'debug':
        msg += ' (%s)' % context.device

    with log.waitfor(msg) as w:
        with context.quiet:
            reply = adb(['push', local_path, remote_path])

        if ' bytes in ' not in reply:
            log.error(reply)

@context.quiet
def read(path, target=None):
    """Download a file from the device, and extract its contents.

    Arguments:
        path(str): Path to the file on the device.
        target(str): Optional, location to store the file.
            Uses a temporary file by default.
    """
    with tempfile.NamedTemporaryFile() as temp:
        target = target or temp.name
        reply  = adb(['pull', path, target])

        if ' bytes in ' not in reply:
            log.error("Could not read %r:\n%s" % (path, reply))

        result = misc.read(target)
    return result

@context.quiet
def write(path, data=''):
    """Create a file on the device with the provided contents.

    Arguments:
        path(str): Path to the file on the device
        data(str): Contents to store in the file
    """
    with tempfile.NamedTemporaryFile() as temp:
        misc.write(temp.name, data)

        reply  = adb(['push', temp.name, path])

        if ' bytes in ' not in reply:
            log.error("Could not read %r:\n%s" % (path, reply))

def process(argv, *a, **kw):
    """Execute a process on the device.

    See ``pwnlib.tubes.process.process`` documentation for more info.

    Returns:
        A ``process`` tube.
    """
    argv = argv or []
    if isinstance(argv, (str, unicode)):
        argv = [argv]
    argv = context.adb + ['shell'] + argv
    return tubes.process.process(argv, *a, **kw)

def interactive(**kw):
    """Spawns an interactive shell."""
    return shell(**kw).interactive()

def shell(**kw):
    """Returns an interactive shell."""
    return process([], **kw)

def which(name):
    """Retrieves the full path to a binary in ``PATH`` on the device"""
    with context.quiet:
        return process(['which', name]).recvall().strip()

def forward(port):
    """Sets up a port to forward to the device."""
    tcp_port = 'tcp:%s' % port
    start_forwarding = adb(['forward', tcp_port, tcp_port])
    atexit.register(lambda: adb(['forward', '--remove', tcp_port]))

@context.quiet
def logcat(stream=False):
    """Reads the system log file.

    By default, causes logcat to exit after reading the file.

    Arguments:
        stream(bool): If ``True``, the contents are streamed rather than
            read in a one-shot manner.  Default is ``False``.

    Returns:
        If ``stream`` is ``False``, returns a string containing the log data.
        Otherwise, it returns a ``tube`` connected to the log output.
    """

    if stream:
        return process(['logcat'])
    else:
        return adb(['logcat', '-d'])

def pidof(name):
    """Returns a list of PIDs for the named process."""
    with context.quiet:
        io = process(['pidof', name])
        data = io.recvall().split()
    return list(map(int, data))

def proc_exe(pid):
    """Returns the full path of the executable for the provided PID."""
    with context.quiet:
        io  = process(['readlink','-e','/proc/%d/exe' % pid])
        data = io.recvall().strip()
    return data

def getprop(name=None):
    """Reads a properties from the system property store.

    Arguments:
        name(str): Optional, read a single property.

    Returns:
        If ``name`` is not specified, a ``dict`` of all properties is returned.
        Otherwise, a string is returned with the contents of the named property.
    """
    with context.quiet:
        if name:
            return process(['getprop', name]).recvall().strip()


        result = process(['getprop']).recvall()

    expr = r'\[([^\]]+)\]: \[(.*)\]'

    props = {}

    for line in result.splitlines():
        if not line.startswith('['):
            continue

        name, value = re.search(expr, line).groups()

        if value.isdigit():
            value = int(value)

        props[name] = value

    return props

def setprop(name, value):
    """Writes a property to the system property store."""
    return process(['setprop', name, value]).recvall().strip()

def listdir(directory='/'):
    """Returns a list containing the entries in the provided directory.

    Note:
        Because ``adb shell`` is used to retrieve the listing, shell
        environment variable expansion and globbing are in effect.
    """
    io = process(['ls', directory])
    data = io.recvall()
    lines = data.splitlines()
    return [l.strip() for l in lines]

def fastboot(args, *a, **kw):
    """Executes a fastboot command.

    Returns:
        The command output.
    """
    serial = context.device
    if not serial:
        log.error("Unknown device")
    return tubes.process.process(['fastboot', '-s', serial] + list(args), **kw).recvall()

def fingerprint():
    """Returns the device build fingerprint."""
    return properties.ro.build.fingerprint

def product():
    """Returns the device product identifier."""
    return properties.ro.build.product

def build():
    """Returns the Build ID of the device."""
    return properties.ro.build.id

class Kernel(object):
    _kallsyms = None

    @property
    @context.quiet
    def symbols(self):
        """Returns a dictionary of kernel symbols"""
        if not self._kallsyms:
            self._kallsyms = {}
            root()
            write('/proc/sys/kernel/kptr_restrict', '1')
            for line in read('/proc/kallsyms').splitlines():
                fields = line.split()
                address = int(fields[0], 16)
                name    = fields[-1]
                self._kallsyms[name] = address
        return self._kallsyms

    @property
    @context.quiet
    def version(self):
        """Returns the kernel version of the device."""
        root()
        return read('/proc/version').strip()

    @property
    @context.quiet
    def cmdline(self):
        root()
        return read('/proc/cmdline').strip()

    def enable_uart(self):
        """Reboots the device with kernel logging to the UART enabled."""
        with log.waitfor('Enabling kernel UART') as w:
            # Check the current commandline, it may already be enabled.
            if any(s.startswith('console=') for s in self.cmdline.split()):
                w.success("Already enabled")
                return

            # Need to be root
            with context.local(device=context.device):
                reboot_bootloader()
                fastboot(['oem','uart','enable'])
                fastboot(['-c'])
                wait_for_device()


kernel = Kernel()

class Property(object):
    def __init__(self, name=None):
        self.__dict__['name'] = name

    def __str__(self):
        return getprop(self.name).strip()

    def __repr__(self):
        return repr(str(self))

    def __getattr__(self, attr):
        if self.name:
            attr = '%s.%s' % (self.name, attr)
        return Property(attr)

    def __setattr__(self, attr, value):
        if attr in self.__dict__:
            return super(Property, self).__setattr__(attr, value)

        if self.name:
            attr = '%s.%s' % (self.name, attr)
        setprop(attr, value)

properties = Property()

def _build_date():
    """Returns the build date in the form YYYY-MM-DD as a string"""
    as_string = getprop('ro.build.date')
    as_datetime =  dateutil.parser.parse(as_string)
    return as_datetime.strftime('%Y-%b-%d')
