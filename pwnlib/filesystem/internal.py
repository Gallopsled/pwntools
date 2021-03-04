# -*- coding: utf-8 -*-
"""
Handles file abstraction for local vs. remote (via ssh)
"""
import os
import six
import tempfile
from pwnlib.context import context
from pwnlib.util.misc import read, write

if six.PY3:
    from pathlib import *
    from pathlib import _PosixFlavour, _Accessor, urlquote_from_bytes
else:
    from pathlib2 import *
    from pathlib2 import _PosixFlavour, _Accessor, urlquote_from_bytes

class _SshPosixFlavour(_PosixFlavour):
    def __init__(self, ssh):
        self.ssh = ssh

    def resolve(self, path, strict=False):
        return context._decode(self.ssh.realpath(path))

    def resolve(self, path):
        return context._decode(self.ssh.realpath(path))

    def make_uri(self, path):
        base = 'ssh://'

        if self.ssh.user:
            base += self.ssh.user
        if self.ssh.password:
            base += ':' + self.ssh.password

        return base + context._encode(path)

    def gethomedir(self, username):
        path = self.ssh.run('realpath ~%s' % username, shell=True)
        return context._decode(path)

class PurePosixPathSSH(PurePath):
    def __init__(self, ssh):
        self._flavour = _ssh_flavour(ssh)

class _SshAccessor(_Accessor):

    def stat(*a, **kw):
        raise NotImplementedError()

    def lstat(*a, **lw):
        raise NotImplementedError()

    def open(*a, **kw):
        raise NotImplementedError()

    def listdir(*a, **kw):
        raise NotImplementedError()

    def scandir(*a, **kw):
        raise NotImplementedError()

    def chmod(*a, **kw):
        raise NotImplementedError()

    def lchmod(*a, **kw):
        raise NotImplementedError()

    def mkdir(*a, **kw):
        raise NotImplementedError()

    def unlink(*a, **kw):
        raise NotImplementedError()

    def link(*a, **kw):
        raise NotImplementedError()

    def rename(*a, **kw):
        raise NotImplementedError()

    def replace(*a, **kw):
        raise NotImplementedError()

    def symlink(*a, **kw):
        raise NotImplementedError()

    def utime(*a, **kw):
        raise NotImplementedError()

    def readlink(*a, **kw):
        raise NotImplementedError()

    def owner(*a, **kw):
        raise NotImplementedError()

    def group(*a, **lw):
        raise NotImplementedError()

_ssh_accessor = _SshAccessor()

class SSHPath2(Path, PurePosixPathSSH):
    """Represents a file that exists on a remote filesystem.
    
    Arguments:
        name(str): Name of the file
        chmod(int): File permission bits
        ssh(ssh): :class:`.ssh` object for manipulating remote files

    Examples:
        >>> s = ssh('travis', 'example.pwnme')
        >>> f = File('/tmp/filename', ssh=s)
        >>> s.realpath(f.name)
        b'/tmp/filename'
        >>> f.write('asdf')
        >>> s.cat(f.name)
        b'asdf'
    """
    def __new__(cls, *args, **kwargs):
        ssh = kwargs.pop('ssh', None)
        if cls is Path:
            cls = SSHPath
        self.ssh = ssh
        self._flavour = _SshPosixFlavour(ssh)
        self = cls._from_parts(args, ssh=ssh)
        return self

    def cwd(self):
        return SSHPath('.', ssh=self.ssh)

    def home(self):
        return self._flavour
        return SSHPath


