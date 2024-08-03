import os
from shutil import which

import pwnlib.args
import pwnlib.filesystem
import pwnlib.gdb
import pwnlib.tubes

log = pwnlib.log.getLogger(__name__)

# abstract class
class pwnvirt():
    """
    start binary inside virtualized environment and return pwnlib.tubes.process.process using Pwnvirt.start()

    Arguments:

        binary(str):
            binary for virtualization debugging
        files(list):
            other files or directories that need to be uploaded to VM
        packages(list):
            packages to install on vm
        symbols(bool):
            additionally install libc6 debug symbols
        tmp(bool):
            if a temporary directory should be created for files
        gdb_port(int):
            specify static gdbserver port
        fast(bool):
            mounts libs locally for faster symbol extraction (experimental)
    """
    LOCAL_DIR = './.pwntools/'
    HOME_DIR = os.path.expanduser('~/share/pwntools/')
    SYSROOT = LOCAL_DIR + 'sysroot/'
    LOCKFILE = LOCAL_DIR + 'vagd.lock'
    SYSROOT_LIB = SYSROOT + 'lib/'
    SYSROOT_LIB_DEBUG = SYSROOT + 'lib/debug'
    KEYFILE = HOME_DIR + 'keyfile'
    PUBKEYFILE = KEYFILE + '.pub'
    DEFAULT_PORT = 2222
    STATIC_GDBSRV_PORT = 42069

    #: if the pwnvirt was newly created (``bool``)
    is_new = False

    _path = None
    _gdb_port = None
    _binary = None
    _ssh = None
    _fast = False

    def __init__(self,
                 binary,
                 libs=False,
                 files=None,
                 packages=None,
                 symbols=True,
                 tmp=False,
                 gdb_port=0,
                 fast=False):

        self._path = binary
        self._gdb_port = gdb_port
        self._binary = './' + os.path.basename(binary)

        pwnlib.context.context.ssh_session = self._ssh

        if tmp:
            self._ssh.set_working_directory()

        if self._sync(self._path):
            self.system('chmod +x ' + self._binary)

        if self.is_new and libs:
            if not (os.path.exists(pwnvirt.LIBS_DIRECTORY)):
                os.makedirs(pwnvirt.LIBS_DIRECTORY)

            self.libs(pwnvirt.LIBS_DIRECTORY)

        if self.is_new and packages is not None:
            if symbols:
                packages.append(pwnvirt.LIBC6_DEBUG)
            try:
                elf = pwnlib.elf.ELF(binary)
                if elf.arch == 'i386':
                    packages.append(pwnvirt.LIBC6_I386)
            except:
                log.warn("failed to get architecture from binary")
            self._install_packages(packages)

        self._fast = fast

        if self._fast:
            self._mount_lib()

        # Copy files to remote
        if isinstance(files, str):
            self._sync(files)
        elif hasattr(files, '__iter__'):
            for file in files:
                self._sync(file)

    def _vm_setup(self):
        """
        setup virtualized machine
        """
        pass

    def _ssh_setup(self):
        """
        setup ssh connection
        """
        pass

    def _sync(self, file):
        """
        upload file on remote if it doesn't exist
        Arguments:

            file(str):
                file to upload

        Returns:
            if the file was uploaded
        """
        sshpath = pwnlib.filesystem.SSHPath(file)
        if not sshpath.exists():
            self.put(file)
            return True
        return False

    _SSHFS_TEMPLATE = \
        'sshfs -p {port} -o StrictHostKeyChecking=no,ro,IdentityFile={keyfile} {user}@{host}:{remote_dir} {local_dir}'

    def _mount(self, remote_dir, local_dir):
        """
        mount remote dir on locally using sshfs

        Arguments:

            remote_dir(str):
                directory on remote to mount
            local_dir(str):
                local mount point
        """
        if not which('sshfs'):
            log.error('sshfs isn\'t installed')
        cmd = pwnvirt._SSHFS_TEMPLATE.format(port=self._ssh.port,
                                             keyfile=self._ssh.keyfile,
                                             user=self._ssh.user,
                                             host=self._ssh.host,
                                             remote_dir=remote_dir,
                                             local_dir=local_dir)
        log.info(cmd)
        os.system(cmd)

    def _lock(self, typ):
        """
        create lock file vor current virtualization type

        Arguments:

            typ(str):
                the type of virtualization
        """
        if not os.path.exists(pwnvirt.LOCAL_DIR):
            os.makedirs(pwnvirt.LOCAL_DIR)

        with open(pwnvirt.LOCKFILE, 'w') as lfile:
            lfile.write(typ)

    def _mount_lib(self, remote_lib='/usr/lib'):
        """
        mount the lib directory of remote

        Arguments:

            remote_lib(str):
                the lib directory to mount locally
        """
        if not (os.path.exists(pwnvirt.SYSROOT) and os.path.exists(pwnvirt.SYSROOT_LIB)):
            os.makedirs(pwnvirt.SYSROOT_LIB)
        if not os.path.ismount(pwnvirt.SYSROOT_LIB):
            log.info('mounting libs in sysroot')
            self._mount(remote_lib, pwnvirt.SYSROOT_LIB)

    def system(self, cmd):
        """
        executes command on vm, interface to :class: pwnlib.tubes.ssh.ssh.system

        Arguments:

            cmd(str):
                command to execute on virtualized environment

        Returns:

            :class:`pwnlib.tubes.ssh.ssh_channel.SSHChannel`
        """
        return self._ssh.system(cmd)

    DEFAULT_PACKAGES = ['gdbserver', 'python3', 'sudo']
    LIBC6_DEBUG = 'libc6-dbg'
    LIBC6_I386 = 'libc6-i386'

    def _install_packages(self, packages):
        """
        install packages on remote machine

        Arguments:

            packages(list):
                packages to install on remote machine
        """
        self.system("sudo apt update").recvall()
        packages_str = " ".join(packages)
        self.system("sudo NEEDRESTART_MODE=a apt install -y {}".format(packages_str)).recvall()

    def put(self, file, remote=None):
        """
        upload file or dir on vm

        Arguments:

            file(str):
                file to upload
            remote(str):
                remote location of file, working directory if not specified
        """
        if os.path.isdir(file):
            self._ssh.upload_dir(file, remote=remote)
        else:
            self._ssh.upload(file, remote=remote)

    def pull(self, file, local=None):
        """
        download file or dir on vm

        Arguments:

            file(str):
                remote location of file, working directory if not specified
            local(str):
                local location of file, current directory if not specified
        """
        sshpath = pwnlib.filesystem.SSHPath(os.path.basename(file))
        if sshpath.is_dir():
            self._ssh.download_dir(file, local=local)
        else:
            self._ssh.download_file(file, local=local)

    LIBS_DIRECTORY = "libs"

    def close(self):
        """
        closing vm
        """
        self._ssh.close()

    def libs(self, directory=None):
        """
        Downloads the libraries referred to by a file.
        This is done by running ldd on the remote server, parsing the output and downloading the relevant files.

        Arguments:

            directory(str):
                Output directory
        """
        for lib in self._ssh._libs_remote(self._binary).keys():
            self.pull(lib, directory + '/' + os.path.basename(lib))

    def debug(self, argv=None, ssh=None, gdb_args=None, gdbscript='', sysroot=None, **kwargs):
        """
        run binary in vm with gdb (pwnlib feature set)

        Arguments:

            argv(list):
                comandline arguments for binary
            ssh(None):
                ignored self._ssh is used instead
            gdb_args(list):
                gdb args to forward to gdb
            gdbscript(str):
                GDB script for GDB
            sysroot(str):
                sysroot dir
            \**kwargs:
                passthrough arguments to pwnlib.gdb.debug

        Returns:
            :class:`pwnlib.tubes.process.process`
        """

        if argv is None:
            argv = list()

        if gdb_args is None:
            gdb_args = list()

        if self._fast:
            if sysroot is not None:
                log.warn('fast enabled but sysroot set, sysroot is ignored')
            sysroot = pwnvirt.SYSROOT_LIB

        if sysroot is not None:
            gdbscript = "set debug-file-directory {}\n".format(pwnvirt.SYSROOT_LIB_DEBUG) + gdbscript

        gdb_args += ["-ex", "file -readnow {}".format(self._path)]

        return pwnlib.gdb.debug([self._binary] + argv, ssh=self._ssh, gdb_args=gdb_args, port=self._gdb_port,
                                gdbscript=gdbscript, sysroot=sysroot, **kwargs)

    def process(self, argv=None, **kwargs):
        """
        run binary in vm as process

        Arguments:

            argv(list):
                commandline arguments for binary
            \**kwargs:
                passthrough arguments to pwnlib.ssh.ssh.process

        Returns:
            :class:`pwnlib.tubes.process.process`
        """
        if argv is None:
            argv = list()
        return self._ssh.process([self._binary] + argv, **kwargs)

    def start(self,
              argv=None,
              gdbscript='',
              api=None,
              sysroot=None,
              gdb_args=None,
              **kwargs):
        """
        start binary on remote and return pwnlib.tubes.process.process

        Arguments:
            argv(list):
                commandline arguments for binary
            gdbscript(str):
                GDB script for GDB
            api(bool):
                if GDB API should be enabled
            sysroot(str):
                sysroot dir
            gdb_args(list):
                extra gdb args
            \**kwargs:
                passthrough arguments

        Returns:
            :class:`pwnlib.tubes.process.process`
        """
        if pwnlib.args.args.GDB:
            return self.debug(argv=argv, gdbscript=gdbscript, gdb_args=gdb_args, sysroot=sysroot,
                              api=api, **kwargs)
        else:
            return self.process(argv=argv, **kwargs)
