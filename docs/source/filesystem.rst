.. testsetup:: *

    import time
    import six
    from pwnlib.context import context
    from pwnlib.tubes.ssh import ssh
    from pwnlib.filesystem import *

    # TODO: Remove global POSIX flag
    import doctest
    doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']

:mod:`pwnlib.filesystem` --- Manipulating Files Locally and Over SSH
====================================================================

Provides a Python2-compatible :py:mod:`pathlib` interface for paths
on the local filesystem (`.Path`) as well as on remote filesystems,
via SSH (`.SSHPath`).

.. automodule:: pwnlib.filesystem
   :members: