from __future__ import absolute_import
from __future__ import division

from pwn import *
from pwnlib.commandline import common

from mako.lookup import TemplateLookup, Template

parser = common.parser_commands.add_parser(
    'template',
    help = 'Generate an exploit template',
    description = 'Generate an exploit template. If no arguments are given, '
                    'the current directory is searched for an executable binary and ' 
                    'libc. If only one binary is found, it is assumed to be the '
                    'challenge binary.'
)

# change path to hardcoded one when building the documentation
printable_data_path = "pwnlib/data" if 'sphinx' in sys.modules else pwnlib.data.path

parser.add_argument('exe', nargs='?', help='Target binary. If not given, the current directory is searched for an executable binary.')
parser.add_argument('--host', help='Remote host / SSH server')
parser.add_argument('--port', help='Remote port / SSH port', type=int)
parser.add_argument('--user', help='SSH Username')
parser.add_argument('--pass', '--password', help='SSH Password', dest='password')
parser.add_argument('--libc', help='Path to libc binary to use. If not given, the current directory is searched for a libc binary.')
parser.add_argument('--path', help='Remote path of file on SSH server')
parser.add_argument('--quiet', help='Less verbose template comments', action='store_true')
parser.add_argument('--color', help='Print the output in color', choices=['never', 'always', 'auto'], default='auto')
parser.add_argument('--template', help='Path to a custom template. Tries to use \'~/.config/pwntools/templates/pwnup.mako\', if it exists. '
                                   'Check \'%s\' for the default template shipped with pwntools.' % 
                                        os.path.join(printable_data_path, "templates", "pwnup.mako"))
parser.add_argument('--no-auto', help='Do not automatically detect missing binaries', action='store_false', dest='auto')

def detect_missing_binaries(args):
    log.info("Automatically detecting challenge binaries...")
    # look for challenge binary, libc, and ld in current directory
    exe, libc, ld = args.exe, args.libc, None
    other_files = []
    for filename in os.listdir():
        if not os.path.isfile(filename):
            continue
        if not libc and ('libc-' in filename or 'libc.' in filename):
            libc = filename
        elif not ld and 'ld-' in filename:
            ld = filename
        else:
            if os.access(filename, os.X_OK):
                other_files.append(filename)
    if not exe:
        if len(other_files) == 1:
            exe = other_files[0]
        elif len(other_files) > 1:
            log.warning("Failed to find challenge binary. There are multiple binaries in the current directory: %s", other_files)

    if exe != args.exe:
        log.success("Found challenge binary %r", exe)
    if libc != args.libc:
        log.success("Found libc binary %r", libc)
    return exe, libc

def main(args):

    lookup = TemplateLookup(
        directories      = [
            os.path.expanduser('~/.config/pwntools/templates/'),
            os.path.join(pwnlib.data.path, 'templates')
        ],
        module_directory = None
    )

    # For the SSH scenario, check that the binary is at the
    # same path on the remote host.
    if args.user:
        if not (args.path or args.exe):
            log.error("Must specify --path or a exe")

        with ssh(args.user, args.host, args.port or 22, args.password or None) as s:
            try:
                remote_file = args.path or args.exe
                s.download(remote_file)
            except Exception:
                log.warning("Could not download file %r, opening a shell", remote_file)
                s.interactive()
                return

        if not args.exe:
            args.exe = os.path.basename(args.path)

    if args.auto and (args.exe is None or args.libc is None):
        args.exe, args.libc = detect_missing_binaries(args)
    
    if args.template:
        template = Template(filename=args.template) # Failing on invalid file is ok
    else:
        template = lookup.get_template('pwnup.mako')
    
    output = template.render(args.exe,
                             args.host,
                             args.port,
                             args.user,
                             args.password,
                             args.libc,
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
    pwnlib.commandline.common.main(__file__, main)
    
