

class NoTcacheError(Exception):
    """Exception raised when tries to access to tcache in glibc when those are
    disabled.
    """

    def __init__(self, message="Tcache are not available in the current glibc"):
        super(NoTcacheError, self).__init__(message)
