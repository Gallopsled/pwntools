import pty, os, select, sys, time, pwn2

pid, fd = pty.fork()

if pid == 0:
    argv = ('/usr/bin/vim',)
    argv = ('/bin/bash',)
    os.execlp(argv[0], *argv)
else:
    # time.sleep(1)
    # sys.stdout.write(os.read(fd, 4096))
    while True:
        rfds, wfds, xfds = select.select([fd, 0], [], [])
        if fd in rfds:
            s = os.read(fd, 4096)
            if not s:
                raise EOFError
            sys.stdout.write(s)
            sys.stdout.flush()
        if 0 in rfds:
            s = os.read(0, 4096)
            if not s:
                raise EOFError
            os.write(fd, s)


# def master_read(fd):
#     import os
#     s = os.read(fd, 4096)
#     return s

# def stdin_read(fd):
#     import os
#     s = os.read(fd, 4096)
#     return s

# pty.spawn('/bin/sh', master_read = master_read, stdin_read = stdin_read)
