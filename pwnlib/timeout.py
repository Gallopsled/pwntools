#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Timeout encapsulation, complete with countdowns and scope managers.
"""
from __future__ import division

import time

import pwnlib


class _DummyContextClass(object):
    def __enter__(self):   pass
    def __exit__(self,*a): pass

_DummyContext = _DummyContextClass()

class _countdown_handler(object):
    def __init__(self, obj, timeout):
        self.obj     = obj
        self.timeout = timeout

    def __enter__(self):
        self.old_timeout  = self.obj._timeout
        self.old_stop     = self.obj._stop

        self.obj._stop    = time.time() + self.timeout

        if self.old_stop:
            self.obj._stop = min(self.obj._stop, self.old_stop)

        self.obj._timeout = self.timeout
    def __exit__(self, *a):
        self.obj._timeout = self.old_timeout
        self.obj._stop    = self.old_stop

class _local_handler(object):
    def __init__(self, obj, timeout):
        self.obj     = obj
        self.timeout = timeout
    def __enter__(self):
        self.old_timeout  = self.obj._timeout
        self.old_stop     = self.obj._stop

        self.obj._stop    = 0
        self.obj._timeout = self.timeout # leverage validation
        self.obj.timeout_change()

    def __exit__(self, *a):
        self.obj._timeout = self.old_timeout
        self.obj._stop    = self.old_stop
        self.obj.timeout_change()

class TimeoutDefault(object):
    def __repr__(self): return "pwnlib.timeout.Timeout.default"
    def __str__(self): return "<default timeout>"

class Maximum(float):
    def __repr__(self):
        return 'pwnlib.timeout.maximum'
maximum = Maximum(2**20)

class Timeout(object):
    """
    Implements a basic class which has a timeout, and support for
    scoped timeout countdowns.

    Valid timeout values are:

    - ``Timeout.default`` use the global default value (``context.default``)
    - ``Timeout.forever`` or :const:`None` never time out
    - Any positive float, indicates timeouts in seconds

    Example:

        >>> context.timeout = 30
        >>> t = Timeout()
        >>> t.timeout == 30
        True
        >>> t = Timeout(5)
        >>> t.timeout == 5
        True
        >>> i = 0
        >>> with t.countdown():
        ...     print(4 <= t.timeout and t.timeout <= 5)
        ...
        True
        >>> with t.countdown(0.5):
        ...     while t.timeout:
        ...         print(round(t.timeout,1))
        ...         time.sleep(0.1)
        0.5
        0.4
        0.3
        0.2
        0.1
        >>> print(t.timeout)
        5.0
        >>> with t.local(0.5):
        ...     for i in range(5):
        ...         print(round(t.timeout,1))
        ...         time.sleep(0.1)
        0.5
        0.5
        0.5
        0.5
        0.5
        >>> print(t.timeout)
        5.0
    """


    #: Value indicating that the timeout should not be changed
    default = TimeoutDefault()

    #: Value indicating that a timeout should not ever occur
    forever = None

    #: Maximum value for a timeout.  Used to get around platform issues
    #: with very large timeouts.
    #:
    #: OSX does not permit setting socket timeouts to 2**22.
    #: Assume that if we receive a timeout of 2**21 or greater,
    #: that the value is effectively infinite.
    maximum = maximum

    def __init__(self, timeout=default):
        self._stop    = 0
        self.timeout = self._get_timeout_seconds(timeout)

    @property
    def timeout(self):
        """
        Timeout for obj operations.  By default, uses ``context.timeout``.
        """
        timeout = self._timeout
        stop    = self._stop

        if not stop:
            return timeout

        return max(stop-time.time(), 0)

    @timeout.setter
    def timeout(self, value):
        assert not self._stop
        self._timeout = self._get_timeout_seconds(value)
        self.timeout_change()

    def _get_timeout_seconds(self, value):
        if value is self.default:
            value = pwnlib.context.context.timeout

        elif value is self.forever:
            value = self.maximum

        else:
            value = float(value)

            if value is value < 0:
                raise AttributeError("timeout: Timeout cannot be negative")

            if value > self.maximum:
                value = self.maximum
        return value

    def countdown_active(self):
        return (self._stop == 0) or (self._stop > time.time())

    def timeout_change(self):
        """
        Callback for subclasses to hook a timeout change.
        """
        pass

    def countdown(self, timeout = default):
        """
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        # Don't count down from infinity
        if timeout is self.maximum:
            return _DummyContext

        if timeout is self.default and self.timeout is self.maximum:
            return _DummyContext

        if timeout is self.default:
            timeout = self._timeout

        return _countdown_handler(self, timeout)

    def local(self, timeout):
        """
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        if timeout is self.default or timeout == self.timeout:
            return _DummyContext

        return _local_handler(self, timeout)
