#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import re

from pwn import *
from pwnlib.commandline import common

from mako.lookup import TemplateLookup

parser = common.parser_commands.add_parser(
    'template',
    help = 'Generate an exploit template'
)

parser.add_argument('exe', nargs='?', help='Target binary')
parser.add_argument('--host', help='Remote host / SSH server')
parser.add_argument('--port', help='Remote port / SSH port', type=int)
parser.add_argument('--user', help='SSH Username')
parser.add_argument('--pass', help='SSH Password', dest='password')
parser.add_argument('--path', help='Remote path of file on SSH server')
parser.add_argument('--quiet', help='Less verbose template comments', action='store_true')

def main(args):
    cache = None

    if cache:
        cache = os.path.join(context.cache_dir, 'mako')

    lookup = TemplateLookup(
        directories      = [os.path.join(pwnlib.data.path, 'templates')],
        module_directory = cache
    )

    # For the SSH scenario, check that the binary is at the
    # same path on the remote host.
    if args.user:
        if not (args.path or args.exe):
            log.error("Must specify --path or a exe")

        s = ssh(args.user, args.host, args.port or 22, args.password or None)
        s.download(args.path or args.exe)

        if not args.exe:
            args.exe = os.path.basename(args.path)

    template = lookup.get_template('pwnup.mako')
    output = template.render(args.exe,
                             args.host,
                             args.port,
                             args.user,
                             args.password,
                             args.path,
                             args.quiet)

    # Fix Mako formatting bs
    output = re.sub('\n\n\n', '\n\n', output)

    print(output)

    if not sys.stdout.isatty():
        try: os.fchmod(sys.stdout.fileno(), 0o700)
        except OSError: pass

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
