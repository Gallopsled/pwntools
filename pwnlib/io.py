# -*- coding: utf-8 -*-
"""
Handles file abstraction for local vs. remote (via ssh)
"""
import os
import tempfile
from pwnlib.util.misc import read, write

class File(object):
	def __init__(self, name, mode=None, ssh=None):
		self.name = name
		self.ssh = ssh

		if not ssh:
			with open(self.name, 'w+') as f:
				if mode:
					os.chmod(self.name, mode)
		else:
			if mode:
				ssh.chmod(oct(mode), self.name)

	def read(self, size=-1):
		if self.ssh:
			return self.ssh.read(self.name)
		return read(self.name)

	def write(self, data):
		if self.ssh:
			return self.ssh.write(self.name, data)
		return write(self.name, data)

class NamedTemporaryFile(File):
	def __init__(self, mode=None, ssh=None):
		if not ssh:
			name = tempfile.NamedTemporaryFile(delete=False).name
		else:
			name = ssh.mktemp()

		super(NamedTemporaryFile, self).__init__(name, mode=mode, ssh=ssh)
