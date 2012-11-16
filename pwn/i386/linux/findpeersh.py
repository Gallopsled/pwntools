from . import *

def findsocksh(port = None):
    """Args: port (defaults to any)
    Finds an open socket which connects to a specified
    port, and then opens a dup2 shell on it."""
    return findsock(port) + dupsh("esi")
