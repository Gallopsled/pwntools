#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Timeout encapsulation, complete with countdowns and scope managers.
"""
import time, logging

log = logging.getLogger(__name__)

class _DummyContextClass(object):
    def __enter__(self):   pass
    def __exit__(self,*a): pass

_DummyContext = _DummyContextClass()

class _countdown_handler(object):
    def __init__(self, obj, timeout):
        self.obj     = obj
        self.timeout = timeout
    def __enter__(self):
        self.saved = (self.obj._timeout, self.obj._start)
        self.obj._start  = time.time()
        if self.timeout is not None:
            self.obj.timeout = self.timeout # leverage validation
    def __exit__(self, *a):
        (self.obj._timeout, self.obj._start) = self.saved

class _local_handler(object):
    def __init__(self, obj, timeout):
        self.obj     = obj
        self.timeout = timeout
    def __enter__(self):
        self.saved = (self.obj._timeout, self.obj._start)
        self.obj._start  = 0
        if self.timeout is not None:
            self.obj.timeout = self.timeout # leverage validation
    def __exit__(self, *a):
        (self.obj._timeout, self.obj._start) = self.saved
        self.obj.timeout_change()


class Timeout(object):
    """
    Implements a basic class which has a timeout, and support for
    scoped timeout countdowns.

    Valid timeout values are:

    - ``Timeout.default`` use the global default value (``context.default``)
    - ``Timeout.forever`` or ``None`` never time out
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
        ...     print (4 < t.timeout and t.timeout < 5)
        ...
        True
        >>> remaining = []
        >>> with t.countdown(0.5):
        ...     while t.timeout:
        ...         print round(t.timeout,1)
        ...         time.sleep(0.1)
        0.5
        0.4
        0.3
        0.2
        0.1
        >>> with t.local(0.5):
        ...     for i in range(5):
        ...         print round(t.timeout,1)
        ...         time.sleep(0.1)
        0.5
        0.5
        0.5
        0.5
        0.5
    """


    #: Value indicating that the timeout should not be changed
    default = object()

    #: Value indicating that a timeout should not ever occur
    forever = None

    #: Maximum value for a timeout.  Used to get around platform issues
    #: with very large timeouts.
    #:
    #: OSX does not permit setting socket timeouts to 2**22.
    #: Assume that if we receive a timeout of 2**21 or greater,
    #: that the value is effectively infinite.
    maximum = 2**20


    def __init__(self, timeout=default):
        self._timeout = self._get_timeout_seconds(timeout)
        self._start   = None


    @property
    def timeout(self):
        """
        Timeout for obj operations.  By default, uses ``context.timeout``.
        """
        timeout = self._timeout
        start   = self._start

        if timeout is Timeout.forever:
            return timeout

        if start:
            timeout -= (time.time() - start)

        return max(timeout, 0)

    @timeout.setter
    def timeout(self, value):
        self._timeout = self._get_timeout_seconds(value)
        self.timeout_change()

    def _get_timeout_seconds(self, value):
        if value is Timeout.default:
            from .context import context
            value = context.timeout

        elif value is Timeout.forever:
            value = Timeout.maximum

        else:
            value = float(value)

            if value is value < 0:
                log.error("Timeout cannot be negative")

            if value > Timeout.maximum:
                value = Timeout.maximum
        return value

    def timeout_change(self):
        """
        Callback for subclasses to hook a timeout change.
        """
        pass

    def countdown(self, timeout):
        """
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If ``None`` is specified for ``timeout``, then the current
        timeout is used is made.  This allows ``None`` to be specified
        as a default argument with less complexity.

        Implementation Detail:

            This reaches around the property() for ``timeout``.
            If we did not do this, we would effectively be setting
            the ``timeout`` property to ``context.timeout`` if the
            former was not set.
        """

        if timeout is Timeout.default and self.timeout is Timeout.forever:
            return _DummyContext

        if timeout is Timeout.forever:
            return _DummyContext

        return _countdown_handler(self, timeout)

    def local(self, timeout):
        """
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        if timeout is Timeout.default:
            return _DummyContext

        return _local_handler(self, timeout)
