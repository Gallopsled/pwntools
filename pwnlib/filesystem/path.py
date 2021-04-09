import six
import tempfile

if six.PY3:
    from pathlib import *
else:
    from pathlib2 import *

@classmethod
def mktemp(cls):
    return cls(tempfile.mktemp())

@classmethod
def mkdtemp(cls):
    return cls(tempfile.mkdtemp())

Path.mktemp = mktemp
Path.mkdtemp = mkdtemp
