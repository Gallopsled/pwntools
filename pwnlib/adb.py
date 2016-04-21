import dateutil.parser
import os
import re
import tempfile

from . import atexit
from . import tubes
from .context import context
from .log import getLogger
from .util import misc

log = getLogger(__name__)

def adb(argv, *a, **kw):
    if isinstance(argv, (str, unicode)):
        argv = [argv]

    serial = kw.pop('serial', None)

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
        wait_for_device(serial)

def reboot(wait=True):
    serial = get_serialno()

    log.info('Rebooting device %s' % serial)
    
    with context.quiet:
        adb('reboot')

    if wait: wait_for_device(serial)

def reboot_bootloader():
    log.info('Rebooting %s to bootloader' % serial)

    with context.quiet:
        adb('reboot-bootloader')

def get_serialno():
    with context.quiet:
        reply = adb('get-serialno')

    if 'unknown' in reply:
        log.error("No devices connected")
    return reply.strip()

def wait_for_device(serial=None):
    msg = "Waiting for device %s to come online" % (serial or '(any)')
    with log.waitfor(msg) as w:
        with context.quiet:
            adb('wait-for-device', serial=serial)

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
        reply = adb(['pull', remote_path, local_path])

        if ' bytes in ' not in reply:
            log.error(reply)

def push(local_path, remote_path):
    msg = "Pushing %r to %r" % (local_path, remote_path) 

    if context.log_level == 'debug':
        msg += ' (%s)' % get_serialno()

    with log.waitfor(msg) as w:
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

def shell(**kw):
    return process([], level='info', **kw).interactive()

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

def fingerprint():
    return getprop('ro.build.fingerprint')

def product():
    return getprop('ro.build.product')

def build():
    return getprop('ro.build.id')

def _build_date():
    """Returns the build date in the form YYYY-MM-DD as a string"""
    as_string = getprop('ro.build.date')
    as_datetime =  dateutil.parser.parse(as_string)
    return as_datetime.strftime('%Y-%b-%d')