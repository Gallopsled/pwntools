from pwn import *

# The purpose of this file is to be able to do something like
#
# import pwn.noargv
#
# or
#
# from pwn.noargv import *

# This should have the same exact same meaning as doing the same without the
# noargv argument, except that we should not parse sys.argv

# This might actually do so in all cases, but that would be pretty unlikely,
# wouldn't it?
