#!/usr/bin/env python2

class Buffer(Exception):
    """
    List of strings with some helper routines.

    Example:

        >>> b = Buffer()
        >>> b.add("A" * 10)
        >>> b.add("B" * 10)
        >>> len(b)
        20
        >>> b.get(1)
        'A'
        >>> len(b)
        19
        >>> b.get(9999)
        'AAAAAAAAABBBBBBBBBB'
        >>> len(b)
        0
        >>> b.get(1)
        ''

    Implementation Details:

        Implemented as a list.  Strings are added onto the end.
        The ``0th`` item in the buffer is the oldest item, and
        will be received first.
    """
    def __init__(self):
        self.data = [] # Buffer
        self.size = 0  # Length


    def __len__(self):
        """
        >>> b = Buffer()
        >>> b.add('lol')
        >>> len(b) == 3
        True
        >>> b.add('foobar')
        >>> len(b) == 9
        True
        """
        return self.size

    def __nonzero__(self):
        return len(self) > 0

    def __contains__(self, x):
        """
        >>> b = Buffer()
        >>> b.add('asdf')
        >>> 'x' in b
        False
        >>> b.add('x')
        >>> 'x' in b
        True
        """
        for b in self.data:
            if x in b:
                return True
        return False

    def index(self, x):
        """
        >>> b = Buffer()
        >>> b.add('asdf')
        >>> b.add('qwert')
        >>> b.index('t') == len(b) - 1
        True
        """
        sofar = 0
        for b in self.data:
            if x in b:
                return sofar + b.index(x)
            sofar += len(b)
        raise IndexError()

    def add(self, data):
        """
        Adds data to the buffer.

        Arguments:
            data(str,Buffer): Data to add
        """
        # Fast path for ''
        if not data: return

        if isinstance(data, Buffer):
            self.size += data.size
            self.data += data.data
        else:
            self.size += len(data)
            self.data.append(data)

    def unget(self, data):
        """
        Places data at the front of the buffer.

        Arguments:
            data(str,Buffer): Data to place at the beginning of the buffer.

        Example:

            >>> b = Buffer()
            >>> b.add("hello")
            >>> b.add("world")
            >>> b.get(5)
            'hello'
            >>> b.unget("goodbye")
            >>> b.get()
            'goodbyeworld'
        """
        if isinstance(data, Buffer):
            self.data = data.data + self.data
            self.size += data.size
        else:
            self.data.insert(0, data)
            self.size += len(data)

    def get(self, want=float('inf')):
        """
        Retrieves bytes from the buffer.

        Arguments:
            want(int): Maximum number of bytes to fetch

        Returns:
            Data as string

        Example:

            >>> b = Buffer()
            >>> b.add('hello')
            >>> b.add('world')
            >>> b.get(1)
            'h'
            >>> b.get()
            'elloworld'
        """
        # Fast path, get all of the data
        if want >= self.size:
            data   = ''.join(self.data)
            self.size = 0
            self.data = []
            return data

        # Slow path, find the correct-index chunk
        have = 0
        i    = 0
        while want >= have:
            have += len(self.data[i])
            i    += 1

        # Join the chunks, evict from the buffer
        data   = ''.join(self.data[:i])
        self.data = self.data[i:]

        # If the last chunk puts us over the limit,
        # stick the extra back at the beginning.
        if have > want:
            extra = data[want:]
            data  = data[:want]
            self.data.insert(0, extra)

        # Size update
        self.size -= len(data)

        return data
