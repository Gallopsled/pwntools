#!/usr/bin/env python3
"""An example of using GDB Python API with Pwntools."""
from pwn import *


def check_write(gdb, exp_buf):
    """Check that write() was called with the expected arguments."""
    fd = gdb.parse_and_eval('$rdi').cast(gdb.lookup_type('int'))
    assert fd == 1, fd
    buf_addr = gdb.parse_and_eval('$rsi').cast(gdb.lookup_type('long'))
    count = gdb.parse_and_eval('$rdx').cast(gdb.lookup_type('long'))
    buf = gdb.selected_inferior().read_memory(buf_addr, count).tobytes()
    assert buf == exp_buf, buf


def demo_sync_breakpoint(cat, gdb, txt):
    """Demonstrate a synchronous breakpoint."""
    # set the synchronous breakpoint on ``write``
    gdb.Breakpoint('write', temporary=True)

    # resume the program
    gdb.continue_nowait()

    # send the line
    cat.sendline(txt)

    # wait until we hit the breakpoint
    gdb.wait()

    # inspect program state
    check_write(gdb, (txt + '\n').encode())

    # resume the program
    gdb.continue_nowait()

    # expect to observe the line we just sent
    cat.recvuntil(txt)


def demo_async_breakpoint(cat, gdb, txt):
    """Demonstrate asynchronous breakpoint."""
    # set the asynchronous breakpoint on ``write``
    class WriteBp(gdb.Breakpoint):
        def __init__(self):
            super().__init__('write')
            self.count = 0

        def stop(self):
            # called in a separate thread
            check_write(gdb, (txt + '\n').encode())
            self.count += 1

    bp = WriteBp()

    # resume the program
    gdb.continue_nowait()

    # send the line and immediately expect to observe it
    cat.sendline(txt)
    cat.recvuntil(txt)

    # check that we hit the breakpoint
    assert bp.count == 1, bp.count

    # interrupt the program
    gdb.interrupt_and_wait()

    # delete the breakpoint
    bp.delete()

    # resume the program
    gdb.continue_nowait()


def main():
    # start ``cat`` under GDB
    with gdb.debug('cat', gdbscript='''
set logging on
set pagination off
''', api=True) as cat:

        # the process is stopped
        # set the synchronous breakpoint on ``read``
        cat.gdb.Breakpoint('read', temporary=True)

        # resume and wait until we hit it
        cat.gdb.continue_and_wait()

        # demonstrate a more interesting synchronous breakpoint
        demo_sync_breakpoint(cat, cat.gdb, 'foo')

        # terminate GDB
        cat.gdb.quit()

    # now start ``cat`` normally
    with process('cat') as cat:
        # attach GDB
        _, cat_gdb = gdb.attach(cat, gdbscript='''
set logging on
set pagination off
''', api=True)

        # the process is stopped
        # demonstrate asynchronous breakpoint
        demo_async_breakpoint(cat, cat_gdb, 'bar')

        # terminate GDB
        cat_gdb.quit()


if __name__ == '__main__':
    main()
