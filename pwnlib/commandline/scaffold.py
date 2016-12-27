#!/usr/bin/env python2
import argparse
import sys
import pkg_resources

from . import common

parser = common.parser_commands.add_parser(
    'scaffold',
    help = '''
Create exploit templates.
''')

parser.add_argument('-s', '--scaffold',
                    dest='scaffold_name',
                    action='append',
                    help=("Add a scaffold to the create process "
                          "(multiple -s args accepted)"))

parser.add_argument('-l', '--list',
                    dest='list',
                    action='store_true',
                    help="List all available scaffold names")

parser.add_argument('--list-templates',
                    dest='list',
                    action='store_true',
                    help=("A backwards compatibility alias for -l/--list. "
                          "List all available scaffold names."))

parser.add_argument('output_file',
                    nargs='?',
                    default=None,
                    help='The file where the exploit will be '
                         'created.')

def show_scaffolds():
    scaffolds = all_scaffolds()
    print(scaffolds)
    scaffolds = sorted(scaffolds, key=lambda x: x.name)
    if scaffolds:
        max_name = max([len(t.name) for t in scaffolds])
        sys.stdout.write('Available scaffolds:\n')
        for scaffold in scaffolds:
            sys.stdout.write('  %s:%s  %s\n' % (
                scaffold.name,
                ' ' * (max_name - len(scaffold.name)), scaffold.summary))
    else:
        sys.stdout.write('No scaffolds available\n')
    return 0

def all_scaffolds():
    scaffolds = []
    eps = list(pkg_resources.iter_entry_points('pwnlib.scaffold'))
    for entry in eps:
        try:
            scaffold_class = entry.load()
            scaffold = scaffold_class(entry.name)
            scaffolds.append(scaffold)
        except Exception as e:  # pragma: no cover
            sys.stdout.write('Warning: could not load entry point %s (%s: %s)\n' % (
                entry.name, e.__class__.__name__, e))
    return scaffolds

def main(args):
    if args.list:
        show_scaffolds()
        return

    if not args.scaffold_name:
        parser.print_usage()
        return

    scaffolds = all_scaffolds()
    print("Using Template: %s" % args.template)

if __name__ == '__main__':
    pwnlib.common.main(__file__)
