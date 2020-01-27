
class MemoryMapFlags:
    """Object with the information of the flags field of maps described in /proc/<pid>/maps

        Arguments:
            readable(bool): True if map is readable
            writable(bool): True if map is writable
            executable(bool): True if map can be executed
            private(bool): True if map is not shared

        Example:

            >>> m = MemoryMapFlags.from_str('rw-p')
            >>> m.readable
            True
            >>> m.writable
            True
            >>> m.executable
            False
            >>> m.private
            True
            >>> m.shared
            False
            >>> str(m)
            'rw-p'
    """

    def __init__(self, readable, writable, executable, private):
        self.readable = readable
        self.writable = writable
        self.executable = executable
        self.private = private

    @property
    def shared(self):
        return not self.private

    @classmethod
    def from_str(cls, flags_str):
        """Generates a MemoryMapFlags object from a flags string. Example: 'r-xp'

        Arguments:
            flags_str(str): Flag string with the format contained in /proc/pid/maps

        Returns:
            MemoryMapFlags: The object representation of the string

         Example:

            >>> str(MemoryMapFlags.from_str('r-xp'))
            'r-xp'
        """
        readable = flags_str[0] == "r"
        writable = flags_str[1] == "w"
        executable = flags_str[2] == "x"
        private = flags_str[3] == "p"
        return cls(readable, writable, executable, private)

    def __str__(self):
        flags_str = ""
        flags_str += "r" if self.readable else "-"
        flags_str += "w" if self.writable else "-"
        flags_str += "x" if self.executable else "-"
        flags_str += "p" if self.private else "s"
        return flags_str


class MemoryMap:
    """Object with the information of the memory maps described in /proc/<pid>/maps

        Arguments:
            start_address(int): The starting address of the map
            end_address(int): The ending address of the map
            flags(MemoryMapFlags): The flags (read, write, exec, private, shared) of the map
            offset(int): Offset of file mapped. 0 if no file
            device_major(int): Device major version. 0 if no file
            device_minor(int): Device minor version. 0 if no file
            inode(int): Inode of the mapped file. 0 if no file
            path(str): Path of the mapped file. Empty string if no file

        Example:

            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> hex(m.start_address)
            '0x55db09b78000'
            >>> hex(m.end_address)
            '0x55db09b81000'
            >>> m.readable
            True
            >>> m.writable
            True
            >>> m.executable
            False
            >>> m.private
            True
            >>> m.shared
            False
            >>> hex(m.offset)
            '0x114000'
            >>> hex(m.device_major)
            '0xfe'
            >>> hex(m.device_minor)
            '0x1'
            >>> m.inode
            9832010
            >>> m.path
            '/usr/bins/bash'
            >>> str(m)
            '55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010\\t\\t/usr/bins/bash'
    """

    def __init__(self, start_address, end_address, flags, offset, device_major, device_minor, inode, path):
        self.start_address = start_address
        self.end_address = end_address
        self.flags = flags
        self.offset = offset
        self.device_major = device_major
        self.device_minor = device_minor
        self.inode = inode
        self.path = path

    @property
    def address(self):
        return self.start_address

    @property
    def size(self):
        """The size of the map"""
        return self.end_address - self.start_address

    @property
    def readable(self):
        return self.flags.readable

    @property
    def writable(self):
        return self.flags.writable

    @property
    def executable(self):
        return self.flags.executable

    @property
    def private(self):
        return self.flags.private

    @property
    def shared(self):
        return self.flags.shared

    def is_in_range(self, address):
        """Indicates if the specified addr is in the range of the map

        Arguments:
            address (int): Memory address

        Returns:
            bool: True if addr is in the map memory range

        Example:
            >>> m = MemoryMap.from_str("55db09b78000-55db09b81000 rw-p 00114000 fe:01 9832010                    /usr/bins/bash")
            >>> m.is_in_range(0x55db09b78000)
            True
            >>> m.is_in_range(0x55db09b81000)
            False
            >>> >>> m.is_in_range(0x55db09b8200)
            True
        """
        return self.start_address <= address < self.end_address

    @classmethod
    def from_str(cls, map_str):
        parts = map_str.split()

        start_address, end_address = parts[0].split("-")
        start_address = int(start_address, 16)
        end_address = int(end_address, 16)

        flags = MemoryMapFlags.from_str(parts[1])

        offset = int(parts[2], 16)

        device_major, device_minor = parts[3].split(":")
        device_major = int(device_major, 16)
        device_minor = int(device_minor, 16)

        inode = int(parts[4])

        try:
            path = parts[5]
        except IndexError:
            path = ""

        return cls(start_address, end_address, flags, offset, device_major, device_minor, inode, path)

    def __str__(self):
        map_str = ""
        map_str += "%x-%x" % (self.start_address, self.end_address)
        map_str += " %s" % self.flags
        map_str += " %08x" % self.offset
        map_str += " %02x:%02x" % (self.device_major, self.device_minor)
        map_str += " %d" % self.inode

        if self.path:
            map_str += "\t\t%s" % self.path

        return map_str


class MemoryMaps:
    """List of the memory maps described in /proc/<pid>/maps

        Arguments:
            maps(list of MemoryMap): The memory maps

        Example:

            >>> maps = MemoryMaps.from_str(\"""561ce1d6f000-561ce1d70000 r--p 00000000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d70000-561ce1d71000 r-xp 00001000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d71000-561ce1d72000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d72000-561ce1d73000 r--p 00002000 fe:01 3676814                    /home/zrt/test
            ... 561ce1d73000-561ce1d74000 rw-p 00003000 fe:01 3676814                    /home/zrt/test
            ... 561ce2895000-561ce28b6000 rw-p 00000000 00:00 0                          [heap]
            ... 7f6e59ff0000-7f6e5a012000 r--p 00000000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a012000-7f6e5a15a000 r-xp 00022000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a15a000-7f6e5a1a6000 r--p 0016a000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a6000-7f6e5a1a7000 ---p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1a7000-7f6e5a1ab000 r--p 001b6000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ab000-7f6e5a1ad000 rw-p 001ba000 fe:01 9831037                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
            ... 7f6e5a1ad000-7f6e5a1b3000 rw-p 00000000 00:00 0
            ... 7f6e5a1cd000-7f6e5a1ce000 r--p 00000000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ce000-7f6e5a1ec000 r-xp 00001000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1ec000-7f6e5a1f4000 r--p 0001f000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f4000-7f6e5a1f5000 r--p 00026000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f5000-7f6e5a1f6000 rw-p 00027000 fe:01 9830423                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
            ... 7f6e5a1f6000-7f6e5a1f7000 rw-p 00000000 00:00 0
            ... 7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0                          [stack]
            ... 7ffd9bb45000-7ffd9bb48000 r--p 00000000 00:00 0                          [vvar]
            ... 7ffd9bb48000-7ffd9bb4a000 r-xp 00000000 00:00 0                          [vdso]
            ... \""")
            >>> str(maps.heap)
            '561ce2895000-561ce28b6000 rw-p 00000000 00:00 0\\t\\t[heap]'
            >>> str(maps.stack)
            '7ffd9bab9000-7ffd9bada000 rw-p 00000000 00:00 0\\t\\t[stack]'
            >>> len(maps)
            22
    """

    def __init__(self, maps):
        self.maps = maps

    @classmethod
    def from_process(cls, pid):
        with open('/proc/%s/maps' % pid) as fmap:
            maps_raw = fmap.read()

        return cls.from_str(maps_raw)

    @classmethod
    def from_str(cls, maps_string):
        maps = [MemoryMap.from_str(line) for line in maps_string.splitlines()]
        return cls(maps)

    def map_with_address(self, address):
        """Returns the map which contains the given address

            Arguments:
                address (int): Memory addr

            Returns:
                MemoryMap or None: Returns MemoryMap in case some map contains
                the address, None otherwise
        """
        for map_ in self.maps:
            if map_.is_in_range(address):
                return map_
        return None

    @property
    def heap(self):
        for map_ in self.maps:
            if map_.path == "[heap]":
                return map_

    @property
    def stack(self):
        for map_ in self.maps:
            if map_.path == "[stack]":
                return map_

    def __str__(self):
        return "\n".join([str(map_) for map_ in self.maps])

    def __len__(self):
        return len(self.maps)

    def __getitem__(self, index):
        return self.maps[index]

    def __iter__(self):
        return iter(self.maps)
