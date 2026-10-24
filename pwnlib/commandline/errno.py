from argparse import Namespace
from typing import Generator
import os
import errno

import pwnlib.constants as constants
from pwnlib.context import context
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
    help='Treat the argument as an errno name or perror substring and print every match.'
)
parser.add_argument(
    '-c', '--context',
    metavar = 'context',
    type    = common.context_arg,
    help    = 'Look the errno values up for this architecture or os, e.g. `-c aarch64`.',
)


def _host_table() -> dict[str, int]:
    """Return ``{name: value}`` for every errno the host standard library knows."""
    return {name: getattr(errno, name) for name in dir(errno)
            if name.isupper() and isinstance(getattr(errno, name), int)}


def _context_table() -> dict[str, int]:
    """Return ``{name: value}`` for the errno numbers ``context`` uses.

    >>> with context.local(arch='amd64', os='linux'):
    ...     _context_table()['ECONNRESET']
    104

    >>> with context.local(arch='mips', os='linux'):
    ...     _context_table()['ECONNRESET']
    131
    """
    if context.os == 'freebsd':
        module = getattr(constants, 'freebsd', None)
    else:
        module = getattr(getattr(constants, context.os, None), context.arch, None)

    if module is None:
        return {}

    table = {}

    for name in _host_table():
        value = getattr(module, name, None)
        if value is not None:
            table[name] = int(getattr(value, 'value', value))

    return table


def _message(name: str) -> str:
    """Return the perror string of ``name`` according to the host, or ``''``."""
    value = getattr(errno, name, None)
    if not isinstance(value, int):
        return ''

    try:
        return os.strerror(value)
    except ValueError:
        return ''


def _iter_known_errnos(table: dict[str, int]) -> Generator[tuple[int, str, str], None, None]:
    """Yield ``(value, name, message)`` tuples sorted by numeric value.

    Aliases sharing a number are reported once, under the first name
    alphabetically.

    >>> with context.local(arch='aarch64', os='linux'):
    ...     [(value, name) for value, name, _ in _iter_known_errnos(_context_table())][:3]
    [(1, 'EPERM'), (2, 'ENOENT'), (3, 'ESRCH')]
    """
    seen = set()

    for name, value in sorted(table.items(), key=lambda item: (item[1], item[0])):
        if value in seen:
            continue
        seen.add(value)
        yield value, name, _message(name)


def _print_errno(value: int, name: str | None = None, message: str | None = None) -> None:
    if name is None:
        name = errno.errorcode.get(value, '')
    if message is None:
        message = os.strerror(value)
    if name:
        print('#define %s %d' % (name, value))
    else:
        print('#define <unknown> %d' % value)
    if message:
        print(message)


def _search_errnos(needle: str, table: dict[str, int]) -> list[tuple[int, str, str]]:
    """Return errnos whose name or ``strerror`` text contains ``needle``.

    The match is case-insensitive, so ``pwn errno -c mips -s conn`` finds the
    connection-oriented errnos even when the host cannot spell them out.

    >>> with context.local(arch='mips', os='linux'):
    ...     [(value, name) for value, name, _ in _search_errnos('econnreset', _context_table())]
    [(131, 'ECONNRESET')]
    """
    needle = needle.lower()
    return [(v, n, m) for v, n, m in _iter_known_errnos(table)
            if needle in n.lower() or needle in m.lower()]


def main(args: Namespace) -> None:
    if args.context is None:
        table = _host_table()
    else:
        table = _context_table()

        if not table:
            print('No errno values known for %s/%s' % (context.os, context.arch))
            return

    if args.list:
        for value, name, message in _iter_known_errnos(table):
            print('%-3d %-10s %s' % (value, name, message))
        return

    if args.error is None:
        parser.error('the following arguments are required: error (or pass --list)')

    if args.search:
        matches = _search_errnos(args.error, table)
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

        name = next((n for n, v in sorted(table.items()) if v == value), None)

        if name is None:
            print("No errno for %s" % value)
            return

    except ValueError:
        name = args.error.upper()
        value = table.get(name)

        if value is None:
            # Fall back to a substring search against perror messages so
            # ``pwn errno 'Cannot allocate memory'`` resolves to ENOMEM.
            matches = _search_errnos(args.error, table)
            if not matches:
                print("No errno for %s" % args.error)
                return
            for value, name, message in matches:
                _print_errno(value, name, message)
                if len(matches) > 1:
                    print()
            return

    _print_errno(value, name, _message(name))


if __name__ == '__main__':
    common.main(__file__, main)
