import tempfile

from pathlib import *

@classmethod
def mktemp(cls):
    return cls(tempfile.mktemp())

@classmethod
def mkdtemp(cls):
    return cls(tempfile.mkdtemp())

Path.mktemp = mktemp
Path.mkdtemp = mkdtemp
