"""The pwnlib is not a big truck! It's a series of tubes!

This is our library for talking to sockets, processes, ssh connections etc.
Our goal is to be able to use the same API for e.g. remote TCP servers, local
TTY-programs and programs run over over SSH.

It is organized such that the majority of the functionality is implemented
in :class:`pwnlib.tubes.tube`. The remaining classes should only implement
just enough for the class to work and possibly code pertaining only to
that specific kind of tube.
"""

__all__ = ['tube', 'sock', 'remote', 'listen', 'process', 'serialtube', 'ssh']

from . import listen
from . import process
from . import remote
from . import serialtube
from . import sock
from . import ssh
from . import tube
