#!/usr/bin/env python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import shutil
import sys

import pwnlib.args
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'libcdb',
    help = 'Print various information about a libc binary',
    description = 'Print various information about a libc binary'
)

libc_commands = parser.add_subparsers(
    dest = 'libc_command'
)

lookup_parser = libc_commands.add_parser(
    'lookup',
    help = 'Lookup a libc version by function offsets',
    description = 'Lookup a libc version by function offsets'
)

lookup_parser.add_argument(
    'symbol_offset_pairs',
    metavar = 'symbol_offset_pairs',
    nargs = '+',
    help = 'Symbol and offset pairs to lookup matching libc version. Can be any number of pairs to narrow the search. Example: "read 3e0 write 520"'
)

lookup_parser.add_argument(
    '-d', '--download-libc',
    action = 'store_true',
    default = False,
    help = 'Attempt to download the matching libc.so'
)

lookup_parser.add_argument(
    '--no-unstrip',
    action = 'store_false',
    dest = 'unstrip',
    help = 'Do NOT attempt to unstrip the libc binary with debug symbols from a debuginfod server'
)

lookup_parser.add_argument(
    '--offline-only',
    action = 'store_true',
    default = False,
    dest = 'offline_only',
    help = 'Attempt to searching with offline only mode'
)

hash_parser = libc_commands.add_parser(
    'hash',
    help = 'Display information of a libc version given an unique hash',
    description = 'Display information of a libc version given an unique hash'
)

hash_parser.add_argument(
    'hash_value',
    metavar = 'hash_value',
    nargs = '+',
    help = 'Hex encoded hash value'
)

hash_parser.add_argument(
    '-t', '--hash_type',
    nargs = '?',
    type = str,
    choices = ['id', 'buildid', 'md5', 'sha1', 'sha256'],
    default = 'buildid',
    help = 'The type of the provided hash value. Supported hashtypes: id, buildid, md5, sha1, sha256'
)

hash_parser.add_argument(
    '-d', '--download-libc',
    action = 'store_true',
    default = False,
    help = 'Attempt to download the matching libc.so'
)

hash_parser.add_argument(
    '--no-unstrip',
    action = 'store_false',
    dest = 'unstrip',
    help = 'Do NOT attempt to unstrip the libc binary with debug symbols from a debuginfod server'
)

hash_parser.add_argument(
    '--offline-only',
    action = 'store_true',
    default = False,
    dest = 'offline_only',
    help = 'Attempt to searching with offline only mode'
)

file_parser = libc_commands.add_parser(
    'file',
    help = 'Dump information about a libc binary',
    description = 'Dump information about a libc binary'
)

file_parser.add_argument(
    'files',
    metavar = 'files',
    nargs = '+',
    help = 'Libc binary to dump'
)

file_parser.add_argument(
    '-s', '--symbols',
    metavar = 'symbols',
    nargs = '*',
    help = 'List of symbol offsets to dump in addition to the common ones'
)

file_parser.add_argument(
    '-o', '--offset',
    metavar = 'offset',
    type = str,
    help = 'Display all offsets relative to this symbol'
)

file_parser.add_argument(
    '--unstrip',
    action = 'store_true',
    dest = 'unstrip',
    help = 'Attempt to unstrip the libc binary inplace with debug symbols from a debuginfod server'
)

fetch_parser = libc_commands.add_parser(
    'fetch',
    help = 'Fetch libc database',
    description = 'Fetch libc database. If no argument passed, it will init and upgrade libc-database repository',
)

fetch_parser.add_argument(
    'path',
    nargs = '?',
    default = context.local_libcdb,
    help = 'Set libc-database path, If it is empty, the default path will be `context.local_libcdb` (%s)' % context.local_libcdb
)

fetch_parser.add_argument(
    '-u', '--update',
    metavar = 'update',
    nargs = '+',
    choices = ['all', 'ubuntu', 'debian', 'rpm', 'centos', 'arch', 'alpine', 'kali', 'parrotsec', 'launchpad'],
    help = 'Fetch the desired libc categories'
)

common_symbols = ['dup2', 'printf', 'puts', 'read', 'system', 'write']

def print_libc_info(libc):
    log.info('%s', text.red(libc['id']))
    log.indented('\t%-20s %s', text.green('BuildID:'), libc['buildid'])
    log.indented('\t%-20s %s', text.green('MD5:'), libc['md5'])
    log.indented('\t%-20s %s', text.green('SHA1:'), libc['sha1'])
    log.indented('\t%-20s %s', text.green('SHA256:'), libc['sha256'])
    log.indented('\t%s', text.green('Symbols:'))
    for symbol in libc['symbols'].items():
        log.indented('\t%25s = %s', symbol[0], symbol[1])

def print_libc_elf(exe):
    from hashlib import md5, sha1, sha256

    log.info('%s', text.red(os.path.basename(exe.path)))

    libc_version = get_libc_version(exe)
    if libc_version:
        log.indented('%-20s %s', text.green('Version:'), libc_version)

    if exe.buildid:
        log.indented('%-20s %s', text.green('BuildID:'), enhex(exe.buildid))

    log.indented('%-20s %s', text.green('MD5:'), md5(exe.data).hexdigest())
    log.indented('%-20s %s', text.green('SHA1:'), sha1(exe.data).hexdigest())
    log.indented('%-20s %s', text.green('SHA256:'), sha256(exe.data).hexdigest())

    # Always dump the basic list of common symbols
    log.indented('%s', text.green('Symbols:'))
    synthetic_symbols = collect_synthetic_symbols(exe)

    symbols = common_symbols + (args.symbols or []) + synthetic_symbols
    symbols.sort()
    for symbol in symbols:
        if symbol not in exe.symbols:
            log.indented('%25s = %s', symbol, text.red('not found'))
        else:
            log.indented('%25s = %#x', symbol, translate_offset(exe.symbols[symbol], args, exe))

def get_libc_version(exe):
    res = re.search(br'libc[ -](\d+\.\d+)', exe.data)
    if res:
        return res.group(1).decode()
    return None

def translate_offset(offs, args, exe):
    if args.offset:
        if args.offset not in exe.symbols:
            log.info_once('offset symbol %s not found. ignoring.', args.offset)
            return offs
        return offs - exe.symbols[args.offset]
    return offs

def collect_synthetic_symbols(exe):
    available_symbols = []
    try:
        exe.symbols['str_bin_sh'] = next(exe.search(b'/bin/sh\x00'))
        available_symbols.append('str_bin_sh')
    except StopIteration:
        pass

    libc_start_main_return = exe.libc_start_main_return
    if libc_start_main_return > 0:
        exe.symbols['__libc_start_main_ret'] = libc_start_main_return
        available_symbols.append('__libc_start_main_ret')

    return available_symbols

def main(args):
    if len(sys.argv) < 3:
        parser.print_usage()
        sys.exit()

    if args.libc_command == 'lookup':
        pairs = args.symbol_offset_pairs
        if len(pairs) % 2 != 0:
            log.failure('Uneven number of arguments. Please provide "symbol offset" pairs')
            return

        symbols = {pairs[i]:pairs[i+1] for i in range(0, len(pairs), 2)}
        matched_libcs = libcdb.search_by_symbol_offsets(symbols, offline_only=args.offline_only, return_raw=True)

        for libc in matched_libcs:
            print_libc_info(libc)
            if args.download_libc:
                path = libcdb.search_by_build_id(libc['buildid'], args.unstrip)
                if path:
                    shutil.copy(path, './{}.so'.format(libc['id']))

    elif args.libc_command == 'hash':
        inverted_map = {v: k for k, v in libcdb.MAP_TYPES.items()}
        hash_type = inverted_map.get(args.hash_type, args.hash_type)

        for hash_value in args.hash_value:
            path = libcdb.search_by_hash(hash_value, hash_type, unstrip=args.unstrip, offline_only=args.offline_only)
            exe = ELF(path, checksec=False)
            print_libc_elf(exe)

            if args.download_libc:
                # if we cannot get actual libc version then copy with cache name
                shutil.copy(path, './libc-{}.so'.format(get_libc_version(exe) or Path(path).stem))

    elif args.libc_command == 'file':
        for file in args.files:
            if not os.path.exists(file) or not os.path.isfile(file):
                log.failure('File does not exist %s', args.file)
                continue

            if args.unstrip:
                libcdb.unstrip_libc(file)

            print_libc_elf(ELF(file, checksec=False))

    elif args.libc_command == 'fetch':

        if args.update:
            subprocess.check_call(['./get'] + args.update, cwd=args.path)

        else:
            if not Path(args.path).exists():
                if yesno("Would you like to initialize the libc-database repository? "
                         "If the path already exists, this prompt will not display, and automatically upgrade repository."):
                    log.waitfor("init libc-database repository")
                    subprocess.check_call(['git', 'clone', 'https://github.com/niklasb/libc-database/', args.path])
            else:
                log.waitfor("upgrade libc-database repository")
                subprocess.check_call(['git', 'pull'], cwd=args.path)


if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__, main)
