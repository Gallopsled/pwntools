import six
import tempfile

if six.PY3:
    from pathlib import *
else:
    from pathlib2 import *

class Path(PosixPath):
    '''Wrapper around :py:class:`pathlib.Path`

    See the official documentation for a full list of methods.
    Only additions are shown here.
    '''

    # Declared so they don't show up in the docs
    def __new__(*a, **kw):
        ""
        return PosixPath.__new__(*a, **kw)

    def __weakref__(*a, **kw):
        ""
        return PosixPath.__new__(*a, **kw)
    
    @classmethod
    def mktemp(cls):
        """Create a temporary file"""
        return cls(tempfile.mktemp())

    @classmethod
    def mkdtemp(cls):
        """Create a temporary file"""
        return cls(tempfile.mkdtemp())

    def makedirs(self, mode, exist_ok=False):
        """Create a directory, and all of its parents"""
        self.mkdir(mode=mode, parents=True, exist_ok=exist_ok)