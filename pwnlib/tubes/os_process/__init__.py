import sys

if sys.platform == 'win32':
    from pwnlib.tubes.os_process.process_windows import process, PTY, PIPE, STDOUT
else:
    from pwnlib.tubes.os_process.process_linux import process, PTY, PIPE, STDOUT