# -*- coding: utf-8 -*-
"""Abstracting ROP calls
"""
from __future__ import division

from pwnlib.abi import ABI
from pwnlib.context import context
from pwnlib.util import packing

import six

from pwnlib.util.misc import python_2_bytes_compatible, align


class Unresolved(object):
    """
    Encapsulates logic for deferring evaluation of a value used
    in a ROP chain which is in some way self-referential.

    For example, it may be necessary to point to arbitrary data
    appended to the ROP chain, but whose address is not known until
    the full ROP chain is complete (because the data is appended
    after all of the gadgets).
    """
    pass


class CurrentStackPointer(Unresolved):
    """
    Unresolved argument which will be replaced with the address of itself.
    """
    pass


class NextGadgetAddress(Unresolved):
    """
    Unresolved argument which will be replaced with the address of the next
    gadget on the stack.

    This is useful for gadgets which set the stack pointer to an absolute
    value, when we wish to continue "execution" of the ROP stack at the
    next gadget.  In particular, SROP needs this.
    """
    pass


class StackAdjustment(Unresolved):
    """
    Placeholder for a ROP gadget which will adjust the stack pointer such
    that "execution" continues at the next ROP gadget.

    This is necessary for ABIs which place arguments on the stack.

    If no stack adjustment is necessary (e.g. a call with no stack-based
    arguments), no data is emitted and the ROP will fall-through to the
    next gadget.
    """
    pass


@python_2_bytes_compatible
class AppendedArgument(Unresolved):
    r"""
    Encapsulates information about a pointer argument, and the data
    which is pointed to, where the absolute address of the data must
    be known, and the data can be appended to the ROP chain.

    Examples:

        >>> context.clear()
        >>> context.arch = 'amd64'
        >>> u = AppendedArgument([1,2,'hello',3])
        >>> len(u)
        32
        >>> u.resolve()
        [1, 2, b'hello\x00$$', 3]

        >>> u = AppendedArgument([1,2,['hello'],3])
        >>> u.resolve()
        [1, 2, 32, 3, b'hello\x00$$']
        >>> u.resolve(10000)
        [1, 2, 10032, 3, b'hello\x00$$']
        >>> u.address = 20000
        >>> u.resolve()
        [1, 2, 20032, 3, b'hello\x00$$']

        >>> u = AppendedArgument([[[[[[[[['pointers!']]]]]]]]], 1000)
        >>> u.resolve()
        [1008, 1016, 1024, 1032, 1040, 1048, 1056, 1064, b'pointers!\x00$$$$$$']
    """
    #: Symbolic name of the value.
    name = None

    #: The values to be placed at a known location
    #:
    #: A list of any of the following types:
    #: - int
    #: - str
    #: - UnresolvedArgument (allows nesting)
    values = []

    #: The size of the fully-resolved argument, in bytes
    size = 0

    #: Absolute address of the target data in memory.
    #: When modified, updates recursively.
    address = 0

    def __init__(self, value, address = 0):
        if not isinstance(value, (list, tuple)):
            value = [value]
        self.values = []
        self.address = address
        for v in value:
            if isinstance(v, (list, tuple)):
                self.size += context.bytes
            else:
                try:
                    self.size += align(context.bytes, len(v))
                except TypeError: # no 'len'
                    self.size += context.bytes
        for v in value:
            if isinstance(v, (list, tuple)):
                arg = AppendedArgument(v, self.address + self.size)
                self.size += arg.size
                self.values.append(arg)
            else:
                self.values.append(v)

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        old = self._address
        delta = value - old
        for v in self.values:
            if isinstance(v, Unresolved):
                v.address += delta

        self._address = value

    _address = 0

    def local(self, address):
        original = self.address

        class LocalAddress(object):

            def __enter__(*a, **kw):
                self.address = address

            def __exit__(*a, **kw):
                self.address = original

        return LocalAddress()

    def resolve(self, addr = None):
        """
        Return a flat list of ``int`` or ``str`` objects which can be
        passed to :func:`.flat`.

        Arguments:
            addr(int): Address at which the data starts in memory.
                If :const:`None`, ``self.addr`` is used.
        """
        if addr is None:
            addr = self.address
        with self.local(addr):
            self.address = addr
            rv = [None] * len(self.values)
            for i, value in enumerate(self.values):
                if isinstance(value, six.integer_types):
                    rv[i] = value
                if isinstance(value, six.text_type):
                    value = context._encode(value)
                if isinstance(value, (bytes, bytearray)):
                    value += b'\x00'
                    while len(value) % context.bytes:
                        value += b'$'

                    rv[i] = value
                if isinstance(value, Unresolved):
                    rv[i] = value.address
                    rv.extend(value.resolve())
                assert rv[i] is not None

        return rv

    def __len__(self):
        return self.size

    def __bytes__(self):
        return packing.flat(self.resolve())

    def __repr__(self):
        if isinstance(self.address, six.integer_types):
            return '%s(%r, %#x)' % (self.__class__.__name__, self.values, self.address)
        else:
            return '%s(%r, %r)' % (self.__class__.__name__, self.values, self.address)


class Call(object):
    """
    Encapsulates ABI-agnostic information about a function call, which is
    to be executed with ROP.

    All non-integer arguments are assumed to be pointer arguments.
    The raw data is placed at the end of the ROP chain, and the argument
    is replaced with an exact pointer to the argument.

    Example:

        >>> Call('system', 0xdeadbeef, [1, 2, '/bin/sh'])
        Call('system', 0xdeadbeef, [1, 2, AppendedArgument(['/bin/sh'], 0x0)])
    """
    #: Pretty name of the call target, e.g. 'system'
    name = None

    #: Address of the call target
    target = 0

    #: Arguments to the call
    args = []

    def __init__(self, name, target, args, abi=None, before=()):
        assert isinstance(name, (bytes, six.text_type))
        # assert isinstance(target, six.integer_types)
        assert isinstance(args, (list, tuple))
        self.abi  = abi or ABI.default()
        self.name = name
        self.target = target
        self.args = list(args)
        for i, arg in enumerate(args):
            if not isinstance(arg, six.integer_types+(Unresolved,)):
                self.args[i] = AppendedArgument(arg)
        self.stack_arguments_before = before

    def __repr__(self):
        fmt = "%#x" if isinstance(self.target, six.integer_types) else "%r"
        return '%s(%r, %s, %r)' % (self.__class__.__name__,
                                    self.name,
                                    fmt % self.target,
                                    self.args)

    @property
    def register_arguments(self):
        return dict(zip(self.abi.register_arguments, self.args))

    @property
    def stack_arguments(self):
        return self.args[len(self.abi.register_arguments):]

    @classmethod
    def _special_repr(cls, x):
        if isinstance(x, AppendedArgument):
            x = x.values
        if isinstance(x, list):
            return list(map(cls._special_repr, x))
        else:
            return x

    def __str__(self):
        fmt = "%#x" if isinstance(self.target, six.integer_types) else "%r"
        args = []
        for arg in self.args:
            args.append(self._special_repr(arg))

        name = self.name or (fmt % self.target)
        arg_str = []
        for arg in args:
            if isinstance(arg, six.integer_types) and arg > 0x100:
                arg_str.append(hex(arg))
            else:
                arg_str.append(str(arg))
        return '%s(%s)' % (name, ', '.join(arg_str))
