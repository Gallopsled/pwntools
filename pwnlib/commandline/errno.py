from __future__ import absolute_import, print_function

import argparse
import os
import errno

from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'errno',
    help = 'Prints out error messages',
    description = 'Prints out error messages'
)

parser.add_argument(
    'error', help='Error message or value', type=str
)

def main(args):
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
    name = args.error.upper()

    if not hasattr(errno, name):
      print("No errno for %s" % name)
      return

    value = getattr(errno, name)


  print('#define', name, value)
  print(os.strerror(value))

if __name__ == '__main__':
    common.main(__file__)
