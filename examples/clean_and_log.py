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

os.system('''((
echo prefix sometext ;
echo prefix someothertext ;
echo here comes the flag ;
echo LostInTheInterTubes
) | nc -l 1337) &
''')

r = remote('localhost', 1337)
atexit.register(r.clean_and_log)

while True:
    line = r.recvline()
    print(re.findall(r'^prefix (\S+)$', line)[0])
