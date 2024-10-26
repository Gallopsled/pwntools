"""
Use case for `pwnlib.tubes.tube.clean_and_log`.

Sometimes you will have a solution to a challenge but you don't know what it
will look like when you get the flag.  Sometimes that will leave you with a
top-level exception, no flag, and angry team members.

Solution:
 1. Always run wireshark or tcpdump.  Always.
 2. Register <your socket>.clean or <your socket>.clean_and_log to run at exit.
"""

from pwn import *
from multiprocessing import Process

def submit_data():
    with context.quiet:
        with listen(1337) as io:
            io.wait_for_connection()
            io.sendline(b'prefix sometext')
            io.sendline(b'prefix someothertext')
            io.sendline(b'here comes the flag')
            io.sendline(b'LostInTheInterTubes')

if __name__ == '__main__':
    p = Process(target=submit_data)
    p.start()

    r = remote('localhost', 1337)
    atexit.register(r.clean_and_log)

    while True:
        line = r.recvline()
        print(re.findall(br'^prefix (\S+)$', line)[0])
