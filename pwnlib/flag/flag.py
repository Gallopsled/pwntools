"""Describes a way to submit a key to a key server.
"""
from __future__ import absolute_import
from __future__ import division

import os

from pwnlib.args import args
from pwnlib.log import getLogger
from pwnlib.tubes.remote import remote
from pwnlib.util.misc import write

log = getLogger(__name__)

#: Default values used for :func:`.submit_flag`
DEFAULTS = {
    'server': 'flag-submission-server',
    'exploit': 'unnamed-exploit',
    'target': 'unknown-target',
    'port': '31337',
    'proto': 'tcp',
    'team': 'unknown-team',
    'file': ''
}

#: Argument names used for :func:`.submit_flag` (see :mod:`pwnlib.args`).
#:
#: Used e.g. ``python exploit.py FLAG_HOST=foo.bar.com`` or
#: ``PWNLIB_FLAG_HOST=foo.bar.com python exploit.py``
ARGS = {
    'server':  'FLAG_HOST',
    'exploit': 'EXPLOIT_NAME',
    'target':  'TARGET_HOST',
    'port':    'FLAG_PORT',
    'proto':   'FLAG_PROTO',
    'team':    'TEAM_NAME',
    'file':    'FLAG_FILE',
}

def _get_env_default(name):
    value = args.get(ARGS[name], DEFAULTS[name])
    return value.strip()


def submit_flag(flag,
                exploit=None,
                target=None,
                server=None,
                port=None,
                proto=None,
                team=None,
                file=None):
    """
    Submits a flag to the game server

    Arguments:
        flag(str): The flag to submit.
        exploit(str): Exploit identifier, optional
        target(str): Target identifier, optional
        server(str): Flag server host name, optional
        port(int): Flag server port, optional
        proto(str): Flag server protocol, optional

    Optional arguments are inferred from the environment,
    or omitted if none is set.

    Note:
        If ``file`` is specified, ``server`` is not specified
        (or is the default value), ``server`` is ignored.

    Returns:
        A string indicating the status of the key submission,
        or an error code.

    Doctest:

        >>> l = listen()
        >>> _ = submit_flag('the-flag', server='localhost', port=l.lport)
        >>> c = l.wait_for_connection()
        >>> c.recvall().split()
        ['the-flag', 'unnamed-exploit', 'unknown-target', 'unknown-team']

        >>> submit_flag('the-flag', file='./my-flag-file')
        >>> read('./my-flag-file')
        'the-flag\nunnamed-exploit\nunknown-target\nunknown-team\n'
    """
    flag = flag.strip()
    log.success("Flag: %r" % flag)

    server  = server  or _get_env_default('server')
    exploit = exploit or _get_env_default('exploit')
    target  = target  or _get_env_default('target')
    port    = port    or _get_env_default('port')
    proto   = proto   or _get_env_default('proto')
    team    = team    or _get_env_default('team')
    file    = file    or _get_env_default('file')

    data = "\n".join([flag,
                      exploit,
                      target,
                      team,
                      ''])

    if file:
        try:
            write(file, data)
        except Exception as e:
            log.warn("Could not write flag %r to %r (%s)", flag, os.path.realpath(file), e)

    # If the server is the default value, don't attempt to submit
    # the flag to the server if we wrote to file.
    if file and server == DEFAULTS['server']:
        return

    try:
        with remote(server, int(port)) as r:
            r.send(data)
            return r.recvall(timeout=1)
    except Exception as e:
        log.warn("Could not submit flag %r to %s:%s (%s)", flag, server, port, e)
