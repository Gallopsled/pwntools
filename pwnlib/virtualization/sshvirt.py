import time
import pwnlib.tubes.ssh
from pwnlib.virtualization.pwnvirt import pwnvirt

log = pwnlib.log.getLogger(__name__)


class sshvirt(pwnvirt):
    r"""
    ssh virtualization interface for pwntools

    Arguments:
        binary(str):
            binary to execute
        user(str):
            ssh user
        host(str):
            ssh hostname
        port(int):
            ssh port
        keyfile(str):
            ssh keyfile
        password(str):
            ssh password
        ignore_config(bool):
            If :const:`True`, disable usage of ~/.ssh/config and ~/.ssh/authorized_keys
        \**kwargs:
            Passthrough arguments to :class: Pwnvirt

    :meth:`.ssh.process`.
    Running as process (or using start()):

        >>> with open('test', 'w') as f:
        ...     _ = f.write('#!/bin/echo')
        >>> vm = sshvirt('./test', user='travis', host='example.pwnme', password='demopass')
        >>> vm.system('ls ./test').recvall(timeout=1)
        b'./test\n'

        >>> io = vm.process()
        >>> io.recvall(timeout=1)
        b'./test\n'

        >>> io.close()

    Running with gdb (or using start() and args.GDB):

        >>> io = vm.debug(gdbscript='continue')
        >>> io.recvline(timeout=5)
        b'./test\n'
        >>> io.close()

    Running with gdb and api:

    .. doctest::
       :skipif: is_python2

        >>> io = vm.debug(api=True)
        >>> bp = io.gdb.Breakpoint('write', temporary=True)
        >>> io.gdb.continue_and_wait()
        >>> count = io.gdb.parse_and_eval('$rdx')
        >>> long = io.gdb.lookup_type('long')
        >>> int(count.cast(long))
        7
        >>> io.gdb.continue_nowait()
        >>> io.recvline(timeout=1)
        b'./test\n'
        >>> io.close()

    Closing vm (optional):
        >>> vm.close()
    """

    DEFAULT_HOST = 'localhost'
    DEFAULT_PORT = 22
    DEFAULT_USER = 'root'

    _user = None
    _host = None
    _port = 0
    _keyfile = None
    _password = None
    _ssh = None

    def __init__(self,
                 binary,
                 user=DEFAULT_USER,
                 host=DEFAULT_HOST,
                 port=DEFAULT_PORT,
                 keyfile=None,
                 password=None,
                 ignore_config=False,
                 **kwargs):
        self._user = user
        self._host = host
        self._port = port
        self._keyfile = keyfile
        self._password = password
        self._ignore_config = ignore_config

        self._ssh_setup()

        super(sshvirt, self).__init__(binary=binary, **kwargs)

    def bind(self, port):
        """
        bind port from ssh connection locally
        :param port:
        :return:
        """

        remote = self._ssh.connect_remote('127.0.0.1', port)
        listener = pwnlib.tubes.listen.listen(0)
        port = listener.lport

        # Disable showing GDB traffic when debugging verbosity is increased
        remote.level = 'error'
        listener.level = 'error'

        # Hook them up
        remote.connect_both(listener)

        return port

    def _vm_setup(self):
        """
        pass
        """
        pass

    _TRIES = 3  # three times the charm

    def _ssh_setup(self):
        """
        setup ssh connection
        """
        progress = log.progress("connecting to ssh")
        for i in range(sshvirt._TRIES):
            try:
                self._ssh = pwnlib.tubes.ssh.ssh(
                    user=self._user,
                    host=self._host,
                    port=self._port,
                    password=self._password,
                    keyfile=self._keyfile,
                    ignore_config=self._ignore_config
                )
                progress.success("Done")
                break
            except:
                if i + 1 >= sshvirt._TRIES:
                    progress.failure('Failed')
                    log.error("Failed to connect to ssh")
                else:
                    progress.status('Trying again')
                # shorter pause for first two tries
                time.sleep(1 if i == 0 else 10)
