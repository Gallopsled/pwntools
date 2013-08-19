from pwn.iterutil import bruteforce
from pwn import md5sumhex
import string

bruteforce(md5sumhex, string.ascii_letters, 3, '9cdfb439c7876e703e307864c9167a15', method='fixed', start=(1,2))
bruteforce(md5sumhex, string.ascii_letters, 3, '9cdfb439c7876e703e307864c9167a15', method='fixed', start=(2,2))

bruteforce(md5sumhex, string.ascii_letters, 3, '9cdfb439c7876e703e307864c9167a15', method='fixed')

bruteforce(md5sumhex, string.ascii_letters, 4, '9cdfb439c7876e703e307864c9167a15', method='upto')
bruteforce(md5sumhex, string.ascii_letters, 4, '9cdfb439c7876e703e307864c9167a15', method='downfrom')
