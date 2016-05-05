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
    if isinstance(argv, (str, unicode)):
        argv = [argv]

    serial = context.device

    print "$ " + ' '.join(['adb'] + argv)

    if serial:
        argv = ['-s', serial] + argv

    return tubes.process.process(context.adb + argv, *a, **kw).recvall()

def root():
    serial = get_serialno()
    log.info("Enabling root on %s" % serial)

    with context.quiet:
        reply  = adb('root')

    if reply and 'restarting adbd as root' not in reply \
    and 'adbd is already running as root' not in reply:
        log.error("Could not run as root:\n%s" % reply)

    with context.quiet:
        wait_for_device(device=serial)

def reboot(wait=True):
    serial = get_serialno()

    log.info('Rebooting device %s' % serial)

    with context.quiet:
        adb('reboot')

    if wait: wait_for_device(device=serial)

def reboot_bootloader():
    serial = get_serialno()
    log.info('Rebooting %s to bootloader' % serial)

    with context.quiet:
        adb('reboot-bootloader')

def get_serialno():
    if context.device:
        return context.device

    with context.quiet:
        reply = adb('get-serialno')

    if 'unknown' in reply:
        log.error("No devices connected")

    return reply.strip()

class Device(object):
    """
    ZX1G22LM7G             device usb:336789504X product:shamu model:Nexus_6 device:shamu features:cmd,shell_v2
    84B5T15A29020449       device usb:336855040X product:angler model:Nexus_6P device:angler
    """
    def __init__(self, serial, type, port, product, model, device):
        self.serial  = serial
        self.type    = type
        self.port    = port
        self.product = product
        self.model   = model
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

        # The last few fields need to be split at colons.
        split  = lambda x: x.split(':')[-1]
        fields[3:] = list(map(split, fields[3:]))

        return Device(*fields[:6])

def devices():
    lines = adb(['devices', '-l'])
    result = []

    for line in lines.splitlines():
        # Skip the first 'List of devices attached' line, and the final empty line.
        if 'List of devices' in line or not line.strip():
            continue
        result.append(Device.from_adb_output(line))

    return tuple(result)

@LocalContext
def wait_for_device():
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
            # There may be multiple devices, so get_serialno() is
            # insufficient.  Pick the first device reported.
            serial = get_serialno()
            w.success('%s (%s %s %s)' % (serial,
                                         product(),
                                         build(),
                                         _build_date()))

    return serial

def foreach(callable=None):
    with context.quiet:
        reply = adb('devices')

    for line in reply.splitlines():
        if 'List of devices' in line:
            continue

        if not line:
            continue

        serial = line.split()[0]

        if callable is None:
            yield serial
            continue

        original = os.environ.get('ANDROID_SERIAL', None)
        try:
            os.environ['ANDROID_SERIAL'] = serial
            callable()
        finally:
            if original is not None:
                os.environ['ANDROID_SERIAL'] = original
            else:
                del os.environ['ANDROID_SERIAL']

def disable_verity():
    with log.waitfor("Disabling dm-verity on %s" % get_serialno()) as w:
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
    with log.waitfor("Remounting filesystem on %s" % get_serialno()) as w:
        disable_verity()
        root()

        with context.quiet:
            reply = adb('remount')

        if 'remount succeeded' not in reply:
            log.error("Could not remount filesystem:\n%s" % reply)

def unroot():
    log.info("Unrooting %s" % get_serialno())
    with context.quiet:
        reply  = adb('unroot')

    if 'restarting adbd as non root' not in reply:
        log.error("Could not run as root:\n%s" % reply)

def pull(remote_path, local_path=None):
    if local_path is None:
        local_path = os.path.basename(remote_path)

    msg = "Pulling %r from %r" % (remote_path, local_path)

    if context.log_level == 'debug':
        msg += ' (%s)' % get_serialno()

    with log.waitfor(msg) as w:
        with context.quiet:
            reply = adb(['pull', remote_path, local_path])

        if ' bytes in ' not in reply:
            log.error(reply)

def push(local_path, remote_path):
    msg = "Pushing %r to %r" % (local_path, remote_path)

    if context.log_level == 'debug':
        msg += ' (%s)' % get_serialno()

    with log.waitfor(msg) as w:
        with context.quiet:
            reply = adb(['push', local_path, remote_path])

        if ' bytes in ' not in reply:
            log.error(reply)

def read(path, target=None):
    with tempfile.NamedTemporaryFile() as temp:
        target = target or temp.name
        reply  = adb(['pull', path, target])

        if ' bytes in ' not in reply:
            log.error("Could not read %r:\n%s" % (path, reply))

        result = misc.read(target)
    return result

def write(path, data=''):
    with tempfile.NamedTemporaryFile() as temp:
        misc.write(temp.name, data)

        reply  = adb(['push', temp.name, path])

        if ' bytes in ' not in reply:
            log.error("Could not read %r:\n%s" % (path, reply))

def process(argv, *a, **kw):
    argv = argv or []
    if isinstance(argv, (str, unicode)):
        argv = [argv]
    argv = context.adb + ['shell'] + argv
    return tubes.process.process(argv, *a, **kw)

def interactive(**kw):
    return shell(**kw).interactive()

def shell(**kw):
    return process([], **kw)

def which(name):
    with context.quiet:
        return process(['which', name]).recvall().strip()

def forward(port):
    tcp_port = 'tcp:%s' % port
    start_forwarding = adb(['forward', tcp_port, tcp_port])
    atexit.register(lambda: adb(['forward', '--remove', tcp_port]))

def logcat(extra='-d'):
    with context.quiet:
        return adb(['logcat', extra])

def logcat_stream():
    with context.local(log_level='debug'):
        return process(['logcat']).recvall()

def pidof(name):
    with context.quiet:
        io = process(['pidof', name])
        data = io.recvall().split()
    return list(map(int, data))

def proc_exe(pid):
    with context.quiet:
        io  = process(['readlink','-e','/proc/%d/exe' % pid])
        data = io.recvall().strip()
    return data

def getprop(name=None):
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
    return process(['setprop', name, value]).recvall().strip()

def listdir(directory='/'):
    io = process(['ls', directory])
    data = io.recvall()
    lines = data.splitlines()
    return [l.strip() for l in lines]

def fastboot(args, *a, **kw):
    """Executes a fastboot command.

    Returns:
        The command output.
    """
    serial = get_serialno()
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
    @property
    def version(self):
        """Returns the kernel version of the device."""
        with context.quiet:
            root()
        return read('/proc/version').strip()

    @property
    def cmdline(self):
        return read('/proc/cmdline').strip()

    def enable_uart(self):
        """Reboots the device with kernel logging to the UART enabled."""
        with log.waitfor('Enabling kernel UART') as w:
            # Check the current commandline, it may already be enabled.
            if any(s.startswith('console=') for s in self.cmdline.split()):
                w.success("Already enabled")
                return

            # Need to be root
            with context.local(device=get_serialno()):
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
