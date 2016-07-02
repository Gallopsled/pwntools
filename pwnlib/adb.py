"""Provides utilities for interacting with Android devices via the Android Debug Bridge.
"""
import glob
import os
import platform
import re
import shutil
import tempfile
import time

import dateutil.parser

from . import atexit
from . import tubes
from .context import context
from .context import LocalContext
from .device import Device
from .log import getLogger
from .util import misc

log = getLogger(__name__)

def adb(argv, *a, **kw):
    """Returns the output of an ADB subcommand."""
    if isinstance(argv, (str, unicode)):
        argv = [argv]

    log.debug("$ " + ' '.join(context.adb + argv))

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

class AdbDevice(Device):
    """Encapsulates information about a connected device."""
    def __init__(self, serial, type, port, product='unknown', model='unknown', device='unknown'):
        self.serial  = serial
        self.type    = type
        self.port    = port
        self.product = product
        self.model   = model.replace('_', ' ')
        self.device  = device

        if product == 'unknown':
            return

        with context.local(device=serial):
            abi = str(properties.ro.product.cpu.abi)
            context.clear()
            context.arch = str(abi)
            self.arch = context.arch
            self.bits = context.bits
            self.endian = context.endian

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
        0062741b0e54b353       unauthorized usb:337641472X
        """

        # The last few fields need to be split at colons.
        split  = lambda x: x.split(':')[-1]
        fields[3:] = list(map(split, fields[3:]))

        return AdbDevice(*fields[:6])

@context.quiet
def devices(serial=None):
    """Returns a list of ``Device`` objects corresponding to the connected devices."""
    lines = adb(['devices', '-l'])
    result = []

    for line in lines.splitlines():
        # Skip the first 'List of devices attached' line, and the final empty line.
        if 'List of devices' in line or not line.strip():
            continue
        device = AdbDevice.from_adb_output(line)
        if device.serial == serial:
            return device
        result.append(device)

    return tuple(result)

@LocalContext
def wait_for_device(kick=False):
    """Waits for a device to be connected."""
    with log.waitfor("Waiting for device to come online") as w:
        with context.quiet:
            if kick:
                try:
                    adb(['reconnect'])
                except Exception:
                    pass
            adb('wait-for-device')

        for device in devices():
            if context.device == device:
                return device
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

            return context.device

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

    result = ''
    with log.waitfor(msg) as w:
        with context.quiet:
            args = context.adb + ['pull', remote_path, local_path]
            io = tubes.process.process(args)
            result = io.recvall()

            if 0 != io.poll(block=True):
                log.error(result)

    return result

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
            args = context.adb + ['push', local_path, remote_path]
            io = tubes.process.process(args)
            result = io.recvall()

            if 0 != io.poll(block=True):
                log.error(result)

    return result

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
        pull(path, target)
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
        push(temp.name, path)

def process(argv, *a, **kw):
    """Execute a process on the device.

    See ``pwnlib.tubes.process.process`` documentation for more info.

    Returns:
        A ``process`` tube.
    """
    argv = argv or []
    if isinstance(argv, (str, unicode)):
        argv = [argv]

    display = argv
    argv = context.adb + ['shell'] + argv

    kw.setdefault('display', display)
    kw.setdefault('where', 'Android')

    return tubes.process.process(argv, *a, **kw)

def interactive(**kw):
    """Spawns an interactive shell."""
    return shell(**kw).interactive()

def shell(**kw):
    """Returns an interactive shell."""
    return process([], **kw)

@context.quiet
def which(name):
    """Retrieves the full path to a binary in ``PATH`` on the device"""
    return process(['which', name]).recvall().strip()

def whoami():
    return process(['whoami']).recvall().strip()

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
    io = process(['find', directory, '-maxdepth', '1', '-print0'])
    data = io.recvall()
    paths = filter(len, data.split('\x00'))
    relpaths = [os.path.relpath(path, directory) for path in paths]
    if '.' in relpaths:
        relpaths.remove('.')
    return relpaths

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
    return str(properties.ro.build.fingerprint)

def product():
    """Returns the device product identifier."""
    return str(properties.ro.build.product)

def build():
    """Returns the Build ID of the device."""
    return str(properties.ro.build.id)

def unlock_bootloader():
    """Unlocks the bootloader of the device.

    Note:
        This requires physical interaction with the device.
    """
    adb(['reboot-bootloader'])
    fastboot(['oem', 'unlock'])
    fastboot(['continue'])

class Kernel(object):
    _kallsyms = None

    @property
    def address(self):
        return self.symbols['_text']

    @property
    @context.quiet
    def symbols(self):
        """Returns a dictionary of kernel symbols"""
        result = {}
        for line in self.kallsyms.splitlines():
            fields = line.split()
            address = int(fields[0], 16)
            name    = fields[-1]
            result[name] = address
        return result

    @property
    @context.quiet
    def kallsyms(self):
        """Returns the raw output of kallsyms"""
        if not self._kallsyms:
            self._kallsyms = {}
            root()
            write('/proc/sys/kernel/kptr_restrict', '1')
            self._kallsyms = read('/proc/kallsyms')
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

    @property
    @context.quiet
    def lastmsg(self):
        root()
        if 'last_kmsg' in listdir('/proc'):
            return read('/proc/last_kmsg')

        if 'console-ramoops' in listdir('/sys/fs/pstore/'):
            return read('/sys/fs/pstore/console-ramoops')

    def enable_uart(self):
        """Reboots the device with kernel logging to the UART enabled."""
        model = str(properties.ro.product.model)

        known_commands = {
            'Nexus 4': None,
            'Nexus 5': None,
            'Nexus 6': 'oem config console enable',
            'Nexus 5X': None,
            'Nexus 6P': 'oem uart enable',
            'Nexus 7': 'oem uart-on',
        }

        with log.waitfor('Enabling kernel UART') as w:

            if model not in known_commands:
                log.error("Device UART is unsupported.")

            command = known_commands[model]

            if command is None:
                w.success('Always enabled')
                return

            # Check the current commandline, it may already be enabled.
            if any(s.startswith('console=tty') for s in self.cmdline.split()):
                w.success("Already enabled")
                return

            # Need to be root
            with context.local(device=context.device):
                # Save off the command line before rebooting to the bootloader
                cmdline = kernel.cmdline

                reboot_bootloader()

                # Wait for device to come online
                while context.device not in fastboot(['devices',' -l']):
                    time.sleep(0.5)

                # Try the 'new' way
                fastboot(command.split())
                fastboot(['continue'])
                wait_for_device()


kernel = Kernel()

class Property(object):
    def __init__(self, name=None):
        self.__dict__['_name'] = name

    def __str__(self):
        return getprop(self._name).strip()

    def __repr__(self):
        return repr(str(self))

    def __getattr__(self, attr):
        if self._name:
            attr = '%s.%s' % (self._name, attr)
        return Property(attr)

    def __setattr__(self, attr, value):
        if attr in self.__dict__:
            return super(Property, self).__setattr__(attr, value)

        if self._name:
            attr = '%s.%s' % (self._name, attr)
        setprop(attr, value)

properties = Property()

def _build_date():
    """Returns the build date in the form YYYY-MM-DD as a string"""
    as_string = getprop('ro.build.date')
    as_datetime =  dateutil.parser.parse(as_string)
    return as_datetime.strftime('%Y-%b-%d')

def find_ndk_project_root(source):
    '''Given a directory path, find the topmost project root.

    tl;dr "foo/bar/jni/baz.cpp" ==> "foo/bar"
    '''
    ndk_directory = os.path.abspath(source)
    while ndk_directory != '/':
        if os.path.exists(os.path.join(ndk_directory, 'jni')):
            break
        ndk_directory = os.path.dirname(ndk_directory)
    else:
        return None

    return ndk_directory

_android_mk_template = '''
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := poc
LOCAL_SRC_FILES := %(local_src_files)s

include $(BUILD_EXECUTABLE)
'''.lstrip()

_application_mk_template = '''
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
APP_ABI:= %(app_abi)s
APP_PLATFORM:=%(app_platform)s
'''.lstrip()

def _generate_ndk_project(file_list, abi='arm-v7a', platform_version=21):
    # Create our project root
    root = tempfile.mkdtemp()

    if not isinstance(file_list, (list, tuple)):
        file_list = [file_list]

    # Copy over the source file(s)
    jni_directory = os.path.join(root, 'jni')
    os.mkdir(jni_directory)
    for file in file_list:
        shutil.copy(file, jni_directory)

    # Create the directories

    # Populate Android.mk
    local_src_files = ' '.join(list(map(os.path.basename, file_list)))
    Android_mk = os.path.join(jni_directory, 'Android.mk')
    with open(Android_mk, 'w+') as f:
        f.write(_android_mk_template % locals())

    # Populate Application.mk
    app_abi = abi
    app_platform = 'android-%s' % platform_version
    Application_mk = os.path.join(jni_directory, 'Application.mk')
    with open(Application_mk, 'w+') as f:
        f.write(_application_mk_template % locals())

    return root

def compile(source):
    """Compile a source file or project with the Android NDK."""

    # Ensure that we can find the NDK.
    ndk = os.environ.get('NDK', None)
    if ndk is None:
        log.error('$NDK must be set to the Android NDK directory')
    ndk_build = os.path.join(ndk, 'ndk-build')

    # Determine whether the source is an NDK project or a single source file.
    project = find_ndk_project_root(source)

    if not project:
        project = _generate_ndk_project(source,
                                        str(properties.ro.product.cpu.abi),
                                        str(properties.ro.build.version.sdk))

    # Remove any output files
    lib = os.path.join(project, 'libs')
    if os.path.exists(lib):
        shutil.rmtree(lib)

    # Build the project
    io = tubes.process.process(ndk_build, cwd=os.path.join(project, 'jni'))

    result = io.recvall()

    if 0 != io.poll():
        log.error("Build failed:\n%s" % result)

    # Find all of the output files
    output = glob.glob(os.path.join(lib, '*', '*'))

    return output[0]

class Partition(object):
    def __init__(self, path, name, blocks=0):
        self.path = path
        self.name = name
        self.blocks = blocks
        self.size = blocks * 1024

    @property
    def data(self):
        with log.waitfor('Fetching %r partition (%s)' % (self.name, self.path)):
            return read(self.path)

class Partitions(object):
    @property
    @context.quiet
    def by_name_dir(self):
        cmd = ['shell','find /dev/block/platform -type d -name by-name']
        return adb(cmd).strip()

    @context.quiet
    def __dir__(self):
        return list(self)

    @context.quiet
    def __iter__(self):
        root()

        # Find all named partitions
        for name in listdir(self.by_name_dir):
            yield name

    @context.quiet
    def __getattr__(self, attr):
        for name in self:
            if name == attr:
                break
        else:
            raise AttributeError("No partition %r" % attr)

        path = os.path.join(self.by_name_dir, name)

        # Find the actual path of the device
        devpath = process(['readlink', '-n', path]).recvall()
        devname = os.path.basename(devpath)

        # Get the size of the partition
        for line in read('/proc/partitions').splitlines():
            if not line.strip():
                continue
            major, minor, blocks, name = line.split(None, 4)
            if devname == name:
                break
        else:
            log.error("Could not find size of partition %r" % name)

        return Partition(devpath, attr, int(blocks))

partitions = Partitions()
