
class HeapError(Exception):
    """Exception raised when there are problems with the heap.
    """

    def __init__(self, message):
        super(HeapError, self).__init__(message)
