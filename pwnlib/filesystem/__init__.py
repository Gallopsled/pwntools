# -*- coding: utf-8 -*-
"""
Handles file abstraction for local vs. remote (via ssh)
"""
from pwnlib.filesystem.path import Path
from pwnlib.filesystem.ssh import SSHPath

__all__ = ['SSHPath', 'Path']
