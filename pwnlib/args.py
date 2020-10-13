"""
Pwntools exposes several magic command-line arguments and environment
variables when operating in `from pwn import *` mode.

The arguments extracted from the command-line and removed from ``sys.argv``.

Arguments can be set by appending them to the command-line, or setting
them in the environment prefixed by ``PWNLIB_``.

The easiest example is to enable more verbose debugging.  Just set ``DEBUG``.

.. code-block:: bash

    $ PWNLIB_DEBUG=1 python exploit.py
    $ python exploit.py DEBUG

These arguments are automatically extracted, regardless of their name, and
exposed via :mod:`pwnlib.args.args`, which is exposed as the global variable
:data:`args`.  Arguments which ``pwntools`` reserves internally are not exposed
this way.

.. code-block:: bash

    $ python -c 'from pwn import *; print(args)' A=1 B=Hello HOST=1.2.3.4 DEBUG
    defaultdict(<type 'str'>, {'A': '1', 'HOST': '1.2.3.4', 'B': 'Hello'})

This is very useful for conditional code, for example determining whether to
run an exploit locally or to connect to a remote server.  Arguments which are
not specified evaluate to an empty string.

.. code-block:: python

    if args['REMOTE']:
        io = remote('exploitme.com', 4141)
    else:
        io = process('./pwnable')

Arguments can also be accessed directly with the dot operator, e.g.:

.. code-block:: python

    if args.REMOTE:
        ...

Any undefined arguments evaluate to an empty string, ``''``.

The full list of supported "magic arguments" and their effects are listed
below.

"""
from __future__ import absolute_import
from __future__ import division

import collections
import logging
import os
import string
import sys

from pwnlib import term
from pwnlib.context import context

class PwnlibArgs(collections.defaultdict):
    def __getattr__(self, attr):
        return self[attr]

args = PwnlibArgs(str)
term_mode  = True
env_prefix = 'PWNLIB_'
free_form  = True

# Check to see if we were invoked as one of the 'pwn xxx' scripts.
# If so, we don't want to remove e.g. "SYS_" from the end of the command
# line, as this breaks things like constgrep.
import pwnlib.commandline
basename = os.path.basename(sys.argv[0])

if basename == 'pwn' or basename in pwnlib.commandline.__all__:
    free_form = False


def isident(s):
    """
    Helper function to check whether a string is a valid identifier,
    as passed in on the command-line.
    """
    first = string.ascii_uppercase + '_'
    body = string.digits + first
    if not s:
        return False
    if s[0] not in first:
        return False
    if not all(c in body for c in s[1:]):
        return False
    return True

def asbool(s):
    """
    Convert a string to its boolean value
    """
    if   s.lower() == 'true':
        return True
    elif s.lower() == 'false':
        return False
    elif s.isdigit():
        return bool(int(s))
    else:
        raise ValueError('must be integer or boolean: %r' % s)

def LOG_LEVEL(x):
    """Sets the logging verbosity used via ``context.log_level``,
    e.g. ``LOG_LEVEL=debug``.
    """
    with context.local(log_level=x):
        context.defaults['log_level']=context.log_level

def LOG_FILE(x):
    """Sets a log file to be used via ``context.log_file``, e.g.
    ``LOG_FILE=./log.txt``"""
    context.log_file=x

def SILENT(x):
    """Sets the logging verbosity to ``error`` which silences most
    output."""
    LOG_LEVEL('error')

def DEBUG(x):
    """Sets the logging verbosity to ``debug`` which displays much
    more information, including logging each byte sent by tubes."""
    LOG_LEVEL('debug')

def NOTERM(v):
    """Disables pretty terminal settings and animations."""
    if asbool(v):
        global term_mode
        term_mode = False

def TIMEOUT(v):
    """Sets a timeout for tube operations (in seconds) via
    ``context.timeout``, e.g. ``TIMEOUT=30``"""
    context.defaults['timeout'] = int(v)

def RANDOMIZE(v):
    """Enables randomization of various pieces via ``context.randomize``"""
    context.defaults['randomize'] = asbool(v)

def NOASLR(v):
    """Disables ASLR via ``context.aslr``"""
    context.defaults['aslr'] = not asbool(v)

def NOPTRACE(v):
    """Disables facilities which require ``ptrace`` such as ``gdb.attach()``
    statements, via ``context.noptrace``."""
    context.defaults['noptrace'] = asbool(v)

def STDERR(v):
    """Sends logging to ``stderr`` by default, instead of ``stdout``"""
    context.log_console = sys.stderr

hooks = {
    'LOG_LEVEL': LOG_LEVEL,
    'LOG_FILE': LOG_FILE,
    'DEBUG': DEBUG,
    'NOTERM': NOTERM,
    'SILENT': SILENT,
    'RANDOMIZE': RANDOMIZE,
    'TIMEOUT': TIMEOUT,
    'NOASLR': NOASLR,
    'NOPTRACE': NOPTRACE,
    'STDERR': STDERR,
}

def initialize():
    global args, term_mode

    # Hack for readthedocs.org
    if 'READTHEDOCS' in os.environ:
        os.environ['PWNLIB_NOTERM'] = '1'

    for k, v in os.environ.items():
        if not k.startswith(env_prefix):
            continue
        k = k[len(env_prefix):]

        if k in hooks:
            hooks[k](v)
        elif isident(k):
            args[k] = v

    argv = sys.argv[:]
    for arg in sys.argv[:]:
        orig  = arg
        value = 'True'

        if '=' in arg:
            arg, value = arg.split('=', 1)

        if arg in hooks:
            sys.argv.remove(orig)
            hooks[arg](value)

        elif free_form and isident(arg):
            sys.argv.remove(orig)
            args[arg] = value

    if term_mode:
        term.init()
