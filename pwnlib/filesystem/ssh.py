# -*- coding: utf-8 -*-
"""
Handles file abstraction for remote SSH files

Emulates pathlib as much as possible, but does so through duck typing.
"""
import os
import six
import sys
import tempfile
import time

from pwnlib.context import context
from pwnlib.util.misc import read, write
from pwnlib.util.packing import _encode, _decode

if six.PY3:
    from pathlib import *
else:
    from pathlib2 import *

class SSHPath(PosixPath):
    r"""Represents a file that exists on a remote filesystem.

    See :class:`.ssh` for more information on how to set up an SSH connection.
    See :py:class:`pathlib.Path` for documentation on what members and
    properties this object has.

    Arguments:
        name(str): Name of the file
        ssh(ssh): :class:`.ssh` object for manipulating remote files

    Note:

        You can avoid having to supply ``ssh=`` on every ``SSHPath`` by setting
        :data:`.context.ssh_session`.  
        In these examples we provide ``ssh=`` for clarity.

    Examples:

        First, create an SSH connection to the server.

        >>> ssh_conn = ssh('travis', 'example.pwnme')

        Let's use a temporary directory for our tests
    
        >>> _ = ssh_conn.set_working_directory()

        Next, you can create SSHPath objects to represent the paths to files
        on the remote system.

        >>> f = SSHPath('filename', ssh=ssh_conn)
        >>> f.touch()
        >>> f.exists()
        True
        >>> f.resolve().path # doctests: +ELLIPSIS
        '/tmp/.../filename'
        >>> f.write_text('asdf ❤️')
        >>> f.read_bytes()
        b'asdf \xe2\x9d\xa4\xef\xb8\x8f'

        ``context.ssh_session`` must be set to use the :meth:`.SSHPath.mktemp`
        or :meth:`.SSHPath.mkdtemp` methods.

        >>> context.ssh_session = ssh_conn
        >>> SSHPath.mktemp() # doctest: +ELLIPSIS
        SSHPath('...', ssh=ssh(user='travis', host='127.0.0.1'))
    """

    sep = '/'

    def __init__(self, path, ssh=None):
        self.path = self._s(path)
        self.ssh = ssh or context.ssh_session

        if self.ssh is None:
            raise ValueError('SSHPath requires an ssh session.  Provide onee or set context.ssh_session.')

    def _s(self, other):
        # We want strings
        if isinstance(other, str):
            return other

        # We don't want unicode
        if isinstance(other, six.text_type):
            return str(other)

        # We also don't want binary
        if isinstance(other, six.binary_type):
            return str(_decode(other))

    def _new(self, path, *a, **kw):
        kw['ssh'] = self.ssh
        path = self._s(path)
        return SSHPath(path, *a, **kw)

    def _run(self, *a, **kw):
        with context.silent:
            return self.ssh.run(*a, **kw)

#---------------------------------- PUREPATH ----------------------------------
    def __str__(self):
        return self.path

    def __fspath__(self):
        return str(self)

    def as_posix(self):
        return self.path

    def __bytes__(self):
        return os.fsencode(self)

    def __repr__(self):
        return "{}({!r}, ssh={!r})".format(self.__class__.__name__, self.as_posix(), self.ssh)

    def as_uri(self):
        raise NotImplementedError()

    def __eq__(self, other):
        if not isinstance(other, SSHPath):
            return str(self) == str(other)

        if self.ssh.host != other.ssh.host:
            return False

        if self.path != other.path:
            return False

        return True

    def __hash__(*a, **kw): ""; raise NotImplementedError
    def __lt__(*a, **kw): ""; raise NotImplementedError
    def __le__(*a, **kw): ""; raise NotImplementedError
    def __gt__(*a, **kw): ""; raise NotImplementedError
    def __ge__(*a, **kw): ""; raise NotImplementedError

    @property
    def anchor(self):
        raise NotImplementedError()

    @property
    def name(self):
        """Returns the name of the file.

        >>> f = SSHPath('hello', ssh=ssh_conn)
        >>> f.name
        'hello'
        """
        return os.path.basename(self.path)

    @property
    def suffix(self):
        """Returns the suffix of the file.

        >>> f = SSHPath('hello.tar.gz', ssh=ssh_conn)
        >>> f.suffix
        '.gz'
        """
        if '.' not in self.name:
            return ''
        return self.name[self.name.rindex('.'):]

    @property
    def suffixes(self):
        """Returns the suffixes of a file

        >>> f = SSHPath('hello.tar.gz', ssh=ssh_conn)
        >>> f.suffixes
        '.tar.gz'
        """

        basename = self.name
        if '.' not in basename:
            return ''
        return '.' + self.name.split('.', 1)[1]

    @property
    def stem(self):
        """Returns the stem of a file without any extension
        
        >>> f = SSHPath('hello.tar.gz', ssh=ssh_conn)
        >>> f.stem
        'hello'
        """
        if '.' not in self.name:
            return self.name
        return self.name[:self.name.index('.')]

    def with_name(self, name):
        """Return a new path with the file name changed

        >>> f = SSHPath('hello/world', ssh=ssh_conn)
        >>> f.path
        'hello/world'
        >>> f.with_name('asdf').path
        'hello/asdf'
        """
        if '/' not in self.path:
            return name

        path, _ = self.path.split(self.sep, 1)
        path = self._new(path)
        return path.joinpath(name)

    def with_stem(self, name):
        """Return a new path with the stem changed.

        >>> f = SSHPath('hello/world.tar.gz', ssh=ssh_conn)
        >>> f.with_stem('asdf').path
        'hello/asdf.tar.gz'
        """
        return self.with_name(name + self.suffixes)

    def with_suffix(self, suffix):
        """Return a new path with the file suffix changed

        >>> f = SSHPath('hello/world.tar.gz', ssh=ssh_conn)
        >>> f.with_suffix('.tgz').path
        'hello/world.tgz'
        """
        return self.with_name(self.stem + suffix)

    def relative_to(self, *other):
        raise NotImplementedError()

    def is_relative_to(self, *other):
        raise NotImplementedError()       

    @property
    def parts(self):
        """Return the individual parts of the path
    
        >>> f = SSHPath('hello/world.tar.gz', ssh=ssh_conn)
        >>> f.parts
        ['hello', 'world.tar.gz']
        """
        return self.path.split(self.sep)

    def joinpath(self, *args):
        """Combine this path with one or several arguments.

        >>> f = SSHPath('hello', ssh=ssh_conn)
        >>> f.joinpath('world').path
        'hello/world'
        """
        newpath = os.path.join(self.path, *args)
        return SSHPath(newpath, ssh=self.ssh)
    
    # __truediv__
    # __rtruediv__

    @property
    def parent(self):
        """Return the parent of this path

        >>> f = SSHPath('hello/world/file.txt', ssh=ssh_conn)
        >>> f.parent.path
        'hello/world'
        """
        a, b = self.path.rsplit(self.sep, 1)
        if a:
            return self._new(a)
        return self

    @property
    def parents(self):
        """Return the parents of this path, as individual parts

        >>> f = SSHPath('hello/world/file.txt', ssh=ssh_conn)
        >>> list(p.path for p in f.parents)
        ['hello', 'world']
        """
        if '/' not in self.path:
            return self._new('.')

        return [self._new(p) for p in self.parent.path.split(self.sep)]

    def is_absolute(self):
        """Returns whether a path is absolute or not.

        >>> f = SSHPath('hello/world/file.txt', ssh=ssh_conn)
        >>> f.is_absolute()
        False

        >>> f = SSHPath('/hello/world/file.txt', ssh=ssh_conn)
        >>> f.is_absolute()
        True
        """
        return self.path.startswith(self.sep)

    def is_reserved(self):
        return False

    def match(self, path_pattern):
        raise NotImplementedError()

#------------------------------------ PATH ------------------------------------

    @property
    def cwd(self):
        return self._new(self.ssh.cwd)

    @property
    def home(self):
        """Returns the home directory for the SSH connection

        >>> f = SSHPath('...', ssh=ssh_conn)
        >>> f.home # doctest: +ELLIPSIS
        SSHPath('/home/...', ssh=ssh(user='...', host='127.0.0.1'))
        """
        path = self._run('echo ~').recvall().rstrip()
        return self._new(path)

    def samefile(self, other_path):
        """Returns whether two files are the same

        >>> a = SSHPath('a', ssh=ssh_conn)
        >>> A = SSHPath('a', ssh=ssh_conn)
        >>> x = SSHPath('x', ssh=ssh_conn)

        >>> a.samefile(A)
        True
        >>> a.samefile(x)
        False
        """
        if not isinstance(other_path, SSHPath):
            return False

        return self.absolute() == other_path.absolute()

    def iterdir(self):
        """Iterates over the contents of the directory

        >>> directory = SSHPath('iterdir', ssh=ssh_conn)
        >>> directory.mkdir()
        >>> fileA = directory.joinpath('fileA')
        >>> fileA.touch()
        >>> fileB = directory.joinpath('fileB')
        >>> fileB.touch()
        >>> dirC = directory.joinpath('dirC')
        >>> dirC.mkdir()
        >>> [p.name for p in directory.iterdir()]
        ['dirC', 'fileA', 'fileB']
        """
        for directory in sorted(self.ssh.sftp.listdir(self.path)):
            yield self._new(directory)

    def glob(self, pattern):
        raise NotImplementedError()

    def rglob(self, pattern):
        raise NotImplementedError()

    def absolute(self):
        """Return the absolute path to a file, preserving e.g. "../".
        The current working directory is determined via the :class:`.ssh`
        member :attr:`.ssh.cwd`.

        Example:
            
            >>> f = SSHPath('absA/../absB/file', ssh=ssh_conn)
            >>> f.absolute().path # doctest: +ELLIPSIS
            '/.../absB/file'
        """
        path = os.path.normpath(self.path)

        if self.is_absolute():
            return self._new(path)

        return self._new(os.path.join(self.ssh.cwd, path))

    def resolve(self, strict=False):
        """Return the absolute path to a file, resolving any '..' or symlinks.
        The current working directory is determined via the :class:`.ssh`
        member :attr:`.ssh.cwd`.

        Note:

            The file must exist to call resolve().

        Examples:

            >>> f = SSHPath('resA/resB/../resB/file', ssh=ssh_conn)

            >>> f.resolve().path # doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            ValueError: Could not normalize path: '/.../resA/resB/file'

            >>> f.parent.absolute().mkdir(parents=True)
            >>> list(f.parent.iterdir())
            []

            >>> f.touch()
            >>> f.resolve() # doctest: +ELLIPSIS
            SSHPath('/.../resA/resB/file', ssh=ssh(user='...', host='127.0.0.1'))
        """
        path = self.absolute().path
        path = os.path.normpath(path)

        if six.PY2:
            error_type = IOError
        else:
            error_type = FileNotFoundError

        try:
            return self._new(self.ssh.sftp.normalize(path))
        except error_type as e:
            raise ValueError("Could not normalize path: %r" % path)

    def stat(self):
        """Returns the permissions and other information about the file

        >>> f = SSHPath('filename', ssh=ssh_conn)
        >>> f.touch()
        >>> stat = f.stat()
        >>> stat.st_size
        0
        >>> '%o' % stat.st_mode # doctest: +ELLIPSIS
        '...664'
        """
        return self.ssh.sftp.stat(self.path)

    def owner(self):
        raise NotImplementedError()

    def group(self):
        raise NotImplementedError()

    def open(self, *a, **kw):
        """Return a file-like object for this path.

        This currently seems to be broken in Paramiko.

        >>> f = SSHPath('filename', ssh=ssh_conn)
        >>> f.write_text('Hello')
        >>> fo = f.open(mode='r+')
        >>> fo                      # doctest: +ELLIPSIS
        <paramiko.sftp_file.SFTPFile object at ...>
        >>> fo.read('asdfasdf')     # doctest: +SKIP
        b'Hello'
        """
        return self.ssh.sftp.open(self.path, *a, **kw)

    def read_bytes(self):
        """Read bytes from the file at this path

        >>> f = SSHPath('/etc/passwd', ssh=ssh_conn)
        >>> f.read_bytes()[:10]
        b'root:x:0:0'
        """
        return self.ssh.read(str(self.absolute()))

    def read_text(self):
        """Read text from the file at this path

        >>> f = SSHPath('/etc/passwd', ssh=ssh_conn)
        >>> f.read_text()[:10]
        'root:x:0:0'
        """
        return self._s(self.read_bytes())

    def write_bytes(self, data):
        r"""Write bytes to the file at this path

        >>> f = SSHPath('somefile', ssh=ssh_conn)
        >>> f.write_bytes(b'\x00HELLO\x00')
        >>> f.read_bytes()
        b'\x00HELLO\x00'
        """
        self.ssh.write(str(self.absolute()), data)

    def write_text(self, data):
        r"""Write text to the file at this path

        >>> f = SSHPath('somefile', ssh=ssh_conn)
        >>> f.write_text("HELLO 😭")
        >>> f.read_bytes()
        b'HELLO \xf0\x9f\x98\xad'
        >>> f.read_text()
        'HELLO 😭'
        """
        data = _encode(data)
        self.write_bytes(data)

    def readlink(self):
        data = self.ssh.readlink(self.path)
        if data == b'':
            data = self.path
        return self._new(data)

    def touch(self):
        """Touch a file (i.e. make it exist)

        >>> f = SSHPath('touchme', ssh=ssh_conn)
        >>> f.exists()
        False
        >>> f.touch()
        >>> f.exists()
        True
        """
        self.ssh.write(self.path, b'')
        # self.ssh.sftp.truncate(self.path, 0)

    def mkdir(self, mode=0o777, parents=False, exist_ok=True):
        r"""Make a directory at the specified path

        >>> f = SSHPath('dirname', ssh=ssh_conn)
        >>> f.mkdir()
        >>> f.exists()
        True

        >>> f = SSHPath('dirA/dirB/dirC', ssh=ssh_conn)
        >>> f.mkdir(parents=True)
        >>> ssh_conn.run(['ls', '-la', f.absolute().path], env={'LC_ALL': 'C.UTF-8'}).recvline()
        b'total 8\n'
        """
        if exist_ok and self.is_dir():
            return

        if not parents:
            self.ssh.sftp.mkdir(self.path, mode=mode)
            return

        if not self.is_absolute():
            path = self._new(self.ssh.cwd)
        else:
            path = self._new('/')

        parts = self.path.split(self.sep)

        for part in parts:
            # Catch against common case, need to normalize path
            if part == '..':
                raise ValueError("Cannot create directory '..'")

            path = path.joinpath(part)

            # Don't create directories that already exist            
            try:
                path.mkdir(mode=mode)
            except OSError:
                raise OSError("Could not create directory %r" % path)

    def chmod(self, mode):
        """Change the permissions of a file

        >>> f = SSHPath('chmod_me', ssh=ssh_conn)
        >>> f.touch() # E
        >>> '0o%o' % f.stat().st_mode
        '0o100664'
        >>> f.chmod(0o777)
        >>> '0o%o' % f.stat().st_mode
        '0o100777'
        """
        self.ssh.sftp.chmod(self.path, mode)

    def lchmod(*a, **kw):
        raise NotImplementedError()

    def unlink(self, missing_ok=False):
        """Remove an existing file.

        TODO:

            This test fails catastrophically if the file name is unlink_me
            (note the underscore)

        Example:

            >>> f = SSHPath('unlink_me', ssh=ssh_conn)
            >>> f.exists()
            False
            >>> f.touch()
            >>> f.exists()
            True
            >>> f.unlink()
            >>> f.exists()
            False

            Note that unlink only works on files.

            >>> f.mkdir()
            >>> f.unlink()
            Traceback (most recent call last):
            ...
            ValueError: Cannot unlink SSHPath(...)): is not a file
        """
        try:
            self.ssh.sftp.remove(str(self))
        except (IOError, OSError) as e:
            if self.exists() and not self.is_file():
                raise ValueError("Cannot unlink %r: is not a file" % self)
            if not missing_ok:
                raise e

    def rmdir(self):
        """Remove an existing directory.

        Example:

            >>> f = SSHPath('rmdir_me', ssh=ssh_conn)
            >>> f.mkdir()
            >>> f.is_dir()
            True
            >>> f.rmdir()
            >>> f.exists()
            False
        """
        if not self.exists():
            return

        if not self.is_dir():
            raise ValueError("Cannot rmdir %r: not a directory" % self)

        self.ssh.sftp.rmdir(self.path)

    def link_to(self, target):
        raise NotImplementedError()

    def symlink_to(self, target):
        r"""Create a symlink at this path to the provided target

        Todo:

            Paramiko's documentation is wrong and inverted.
            https://github.com/paramiko/paramiko/issues/1821

        Example:

            >>> a = SSHPath('link_name', ssh=ssh_conn)
            >>> b = SSHPath('link_target', ssh=ssh_conn)
            >>> a.symlink_to(b)
            >>> a.write_text("Hello")
            >>> b.read_text()
            'Hello'
        """
        if isinstance(target, SSHPath):
            target = target.path

        self.ssh.sftp.symlink(target, self.path)

    def rename(self, target):
        """Rename a file to the target path

        Example:

            >>> a = SSHPath('rename_from', ssh=ssh_conn)
            >>> b = SSHPath('rename_to', ssh=ssh_conn)
            >>> a.touch()
            >>> b.exists()
            False
            >>> a.rename(b)
            >>> b.exists()
            True
        """
        if isinstance(target, SSHPath):
            target = target.path

        self.ssh.sftp.rename(self.path, target)

    def replace(self, target):
        """Replace target file with file at this path

        Example:

            >>> a = SSHPath('rename_from', ssh=ssh_conn)
            >>> a.write_text('A')
            >>> b = SSHPath('rename_to', ssh=ssh_conn)
            >>> b.write_text('B')
            >>> a.replace(b)
            >>> b.read_text()
            'A'
        """
        if isinstance(target, SSHPath):
            target = target.path

        self._new(target).unlink(missing_ok=True)
        self.rename(target)

    def exists(self):
        """Returns True if the path exists

        Example:

            >>> a = SSHPath('exists', ssh=ssh_conn)
            >>> a.exists()
            False
            >>> a.touch()
            >>> a.exists()
            True
            >>> a.unlink()
            >>> a.exists()
            False
        """
        try:
            self.stat()
            return True
        except IOError:
            return False

    def is_dir(self):
        """Returns True if the path exists and is a directory
        
        Example:

            >>> f = SSHPath('is_dir', ssh=ssh_conn)
            >>> f.is_dir()
            False
            >>> f.touch()
            >>> f.is_dir()
            False
            >>> f.unlink()
            >>> f.mkdir()
            >>> f.is_dir()
            True
        """
        if not self.exists():
            return False

        if self.stat().st_mode & 0o040000:
            return True

        return False

    def is_file(self):
        """Returns True if the path exists and is a file
        
        Example:

            >>> f = SSHPath('is_file', ssh=ssh_conn)
            >>> f.is_file()
            False
            >>> f.touch()
            >>> f.is_file()
            True
            >>> f.unlink()
            >>> f.mkdir()
            >>> f.is_file()
            False
        """
        if not self.exists():
            return False

        if self.stat().st_mode & 0o040000:
            return False

        return True

    def is_symlink(self):
        raise NotImplementedError()

    def is_block_device(self):
        raise NotImplementedError()

    def is_char_device(self):
        raise NotImplementedError()

    def is_fifo(self):
        raise NotImplementedError()

    def is_socket(self):
        raise NotImplementedError()

    def expanduser(self):
        """Expands a path that starts with a tilde

        Example:

            >>> f = SSHPath('~/my-file', ssh=ssh_conn)
            >>> f.path
            '~/my-file'
            >>> f.expanduser().path # doctest: +ELLIPSIS
            '/home/.../my-file'
        """
        if not self.path.startswith('~/'):
            return self
        
        home = self.home
        subpath = self.path.replace('~/', '')
        return home.joinpath(subpath)

#----------------------------- PWNTOOLS ADDITIONS -----------------------------
    @classmethod
    def mktemp(cls):
        temp = _decode(context.ssh_session.mktemp())
        return SSHPath(temp, ssh=context.ssh_session)

    @classmethod
    def mkdtemp(self):
        temp = _decode(context.ssh_session.mkdtemp())
        return SSHPath(temp, ssh=context.ssh_session)

__all__ = ['SSHPath']
