#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

from pwn import *
from pwnlib.commandline import common

from mako.lookup import TemplateLookup

parser = common.parser_commands.add_parser(
    'template',
    help = 'Generate an exploit template',
    description = 'Generate an exploit template'
)

parser.add_argument('exe', nargs='?', help='Target binary')
parser.add_argument('--host', help='Remote host / SSH server')
parser.add_argument('--port', help='Remote port / SSH port', type=int)
parser.add_argument('--user', help='SSH Username')
parser.add_argument('--pass', '--password', help='SSH Password', dest='password')
parser.add_argument('--path', help='Remote path of file on SSH server')
parser.add_argument('--quiet', help='Less verbose template comments', action='store_true')
parser.add_argument('--color', help='Print the output in color', choices=['never', 'always', 'auto'], default='auto')

def main(args):
    lookup = TemplateLookup(
        directories      = [os.path.join(pwnlib.data.path, 'templates')],
        module_directory = None
    )

    # For the SSH scenario, check that the binary is at the
    # same path on the remote host.
    if args.user:
        if not (args.path or args.exe):
            log.error("Must specify --path or a exe")

        s = ssh(args.user, args.host, args.port or 22, args.password or None)

        try:
            remote_file = args.path or args.exe
            s.download(remote_file)
        except Exception:
            log.warning("Could not download file %r, opening a shell", remote_file)
            s.interactive()
            return

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

    # Colorize the output if it's a TTY
    if args.color == 'always' or (args.color == 'auto' and sys.stdout.isatty()):
        from pygments import highlight
        from pygments.formatters import TerminalFormatter
        from pygments.lexers.python import PythonLexer
        output = highlight(output, PythonLexer(), TerminalFormatter())

    print(output)

    # If redirected to a file, make the resulting script executable
    if not sys.stdout.isatty():
        try: os.fchmod(sys.stdout.fileno(), 0o700)
        except OSError: pass

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
