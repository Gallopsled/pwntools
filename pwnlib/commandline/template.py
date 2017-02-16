#!/usr/bin/env python2
from __future__ import absolute_import

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
parser.add_argument('--port', help='Remote port / SSH port')
parser.add_argument('--user', help='SSH Username')
parser.add_argument('--pass', help='SSH Password', dest='password')
parser.add_argument('--path', help='Remote path of file on SSH server')

def main(args):
    cache = None

    if cache:
        cache = os.path.join(context.cache_dir, 'mako')

    lookup = TemplateLookup(
        directories      = [os.path.join(pwnlib.data.path, 'templates')],
        module_directory = cache
    )

    template = lookup.get_template('pwnup.mako')
    output = template.render(args.exe,
                             args.host,
                             args.port,
                             args.user,
                             args.password,
                             args.path)

    # Fix Mako formatting bs
    output = re.sub('\n\n\n', '\n\n', output)

    print output

    if not sys.stdout.isatty():
        try: os.fchmod(sys.stdout.fileno(), 0700)
        except OSError: pass

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
