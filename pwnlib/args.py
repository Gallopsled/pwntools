#!/usr/bin/env python2
"""
"""
import collections
import logging
import os
import string
import sys
from .context import context
from . import term

term_mode  = False
args       = collections.defaultdict(str)
env_prefix = 'PWNLIB_'

def isident(s):
    """
    Helper function to check whether a string is a valid identifier,
    as passed in on the command-line.
    """
    first = string.uppercase + '_'
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

def set_log_level(x):
    with context.local(log_level=x):
        context.defaults['log_level']=context.log_level

def set_log_file(x):
    context.log_file=x

def set_log_level_error(x):
    set_log_level('error')

def set_log_level_debug(x):
    set_log_level('debug')

def set_noterm(v):
    if asbool(v):
        global term_mode
        term_mode = False

def set_timeout(v):
    context.defaults['timeout'] = int(v)

def set_randomize(v):
    context.defaults['randomize'] = asbool(v)

def set_multiply(v):
    context.defaults['multiply'] = int(v, 0)

hooks = {
    'LOG_LEVEL': set_log_level,
    'LOG_FILE': set_log_file,
    'DEBUG': set_log_level_debug,
    'NOTERM': set_noterm,
    'SILENT': set_log_level_error,
    'RANDOMIZE': set_randomize,
    'MULTIPLY': set_multiply,
    'TIMEOUT': set_timeout
}

def initialize():
    global args, term_mode

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
            arg, value = arg.split('=')

        if arg in hooks:
            sys.argv.remove(orig)
            hooks[arg](value)

        elif isident(arg):
            sys.argv.remove(orig)
            args[arg] = value

    if term_mode:
        term.init()
