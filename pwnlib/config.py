# -*- coding: utf-8 -*-
"""Allows per-user and per-host configuration of Pwntools settings.

The list of configurable options includes all of the logging symbols
and colors, as well as all of the default values on the global context
object.

The configuration file is read from ``~/.pwn.conf`` and ``/etc/pwn.conf``.

The configuration file is only read in ``from pwn import *`` mode, and not
when used in library mode (``import pwnlib``).  To read the configuration
file in library mode, invoke :func:`.config.initialize`.

The ``context`` section supports complex types, at least as far as is
supported by ``pwnlib.util.safeeval.expr``.

::

    [log]
    success.symbol=😎
    error.symbol=☠
    info.color=blue

    [context]
    adb_port=4141
    randomize=1
    timeout=60
    terminal=['x-terminal-emulator', '-e']
"""
from __future__ import absolute_import

import ConfigParser
import os

registered_configs = {}

def register_config(section, function):
    """Registers a configuration section.

    Arguments:
        section(str): Named configuration section
        function(callable): Function invoked with a dictionary of
            ``{option: value}`` for the entries in the section.
    """
    registered_configs[section] = function

def initialize():
    """Read the configuration files."""
    from pwnlib.log import getLogger
    log = getLogger(__name__)

    c = ConfigParser.ConfigParser()
    c.read(['/etc/pwn.conf', os.path.expanduser('~/.pwn.conf')])

    for section in c.sections():
        if section not in registered_configs:
            log.warn("Unknown configuration section %r" % section)
            continue
        settings = dict(c.items(section))
        registered_configs[section](settings)
