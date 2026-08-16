from argparse import Namespace
from typing import Generator
import os
import errno

from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'errno',
    help = 'Prints out error messages',
    description = 'Prints out error messages'
)

parser.add_argument(
    'error', help='Error message or value (errno number, errno name, or perror string)',
    nargs='?', type=str
)
parser.add_argument(
    '-l', '--list', action='store_true',
    help='List every known errno (number, name, perror string).'
)
parser.add_argument(
    '-s', '--search', action='store_true',
    help='Treat the argument as a perror substring and print every matching errno.'
)


def _iter_known_errnos() -> Generator[tuple[int, str, str], None, None]:
    """Yield ``(value, name, message)`` tuples for every errno code visible to
    the standard library on this platform, sorted by numeric value.
    """
    for value, name in sorted(errno.errorcode.items()):
        yield value, name, os.strerror(value)


def _print_errno(value: int, name: str | None = None, message: str | None = None) -> None:
    if name is None:
        name = errno.errorcode.get(value, '')
    if message is None:
        message = os.strerror(value)
    if name:
        print('#define %s %d' % (name, value))
    else:
        print('#define <unknown> %d' % value)
    print(message)


def _search_errnos(needle: str) -> list[tuple[int, str, str]]:
    """Return errnos whose ``strerror`` text contains ``needle`` (case-insensitive)."""
    needle = needle.lower()
    return [(v, n, m) for v, n, m in _iter_known_errnos() if needle in m.lower()]


def main(args: Namespace) -> None:
    if args.list:
        for value, name, message in _iter_known_errnos():
            print('%-3d %-10s %s' % (value, name, message))
        return

    if args.error is None:
        parser.error('the following arguments are required: error (or pass --list)')

    if args.search:
        matches = _search_errnos(args.error)
        if not matches:
            print("No errno matched %r" % args.error)
            return
        for value, name, message in matches:
            _print_errno(value, name, message)
            print()
        return

    try:
        value = int(args.error, 0)

        if value < 0:
            value = -value

        if 0x100000000 - value < 0x200:
            value = 0x100000000 - value

        if value not in errno.errorcode:
            print("No errno for %s" % value)
            return

        name = errno.errorcode[value]

    except ValueError:
        candidate = args.error.upper()

        if hasattr(errno, candidate):
            name = candidate
            value = getattr(errno, name)
        else:
            # Fall back to a substring search against perror messages so
            # ``pwn errno 'Cannot allocate memory'`` resolves to ENOMEM.
            matches = _search_errnos(args.error)
            if not matches:
                print("No errno for %s" % args.error)
                return
            for value, name, message in matches:
                _print_errno(value, name, message)
                if len(matches) > 1:
                    print()
            return

    _print_errno(value, name)


if __name__ == '__main__':
    common.main(__file__, main)
