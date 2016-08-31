import argparse
import os

from . import common

parser = common.parser_commands.add_parser(
    'errno',
    help = 'Prints out error messages'
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

    if value not in os.errno.errorcode:
      print "No errno for %s" % value
      return

    name = os.errno.errorcode[value]

  except ValueError:
    name = args.error.upper()

    if not hasattr(os.errno, name):
      print "No errno for %s" % name
      return

    value = getattr(os.errno, name)


  print '#define', name, value
  print os.strerror(value)

if __name__ == '__main__':
    pwnlib.common.main(__file__)
