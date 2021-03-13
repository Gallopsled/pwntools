

class NoTcacheError(Exception):
    """Exception raised when tries to access to tcaches and these are
    unavailable in the current libc.
    """

    def __init__(self, message="Tcache are not available in the current libc"):
        super(NoTcacheError, self).__init__(message)
