# -*- coding: utf-8 -*-
"""
Handles file abstraction for local vs. remote (via ssh)
"""
import os
import tempfile
from pwnlib.context import context
from pwnlib.util.misc import read, write

class File(object):
    """Represents a file that exists on either a local or remote system.
    
    Arguments:
        name(str): Name of the file
        chmod(int): File permission bits
        ssh(ssh): :class:`.ssh` object for manipulating remote files

    Examples:

        The class can be used to manipulate files on the local host system

        >>> f = File('filename')
        >>> f.write('asdf')
        >>> f.read()
        b'asdf'
        >>> read(f.name)
        b'asdf'

        But if ``ssh`` is passed, the file is on a remote system.

        >>> s = ssh('travis', 'example.pwnme')
        >>> f = File('/tmp/filename', ssh=s)
        >>> s.realpath(f.name)
        b'/tmp/filename'
        >>> f.write('asdf')
        >>> s.cat(f.name)
        b'asdf'
    """

    def __init__(self, name, chmod=None, ssh=None):
        self.name = name
        self.ssh = ssh

        if not ssh:
            with open(self.name, 'w+') as f:
                if chmod:
                    os.chmod(self.name, chmod)
        else:
            with context.quiet:
                ssh.touch(self.name)
                if chmod:
                    ssh.chmod(oct(chmod), self.name)

    def read(self, size=-1):
        if self.ssh:
            with context.quiet:
                return self.ssh.read(self.name)
        return read(self.name)

    def write(self, data):
        if self.ssh:
            with context.quiet:
                self.ssh.write(self.name, data)
        else:
            write(self.name, data)

class NamedTemporaryFile(File):
    """Automatically create a temporary :class:`.File` on either the
    remote or local system."""
    def __init__(self, chmod=None, ssh=None):
        if not ssh:
            name = tempfile.NamedTemporaryFile(delete=False).name
        else:
            name = ssh.mktemp()

        super(NamedTemporaryFile, self).__init__(name, chmod=chmod, ssh=ssh)
