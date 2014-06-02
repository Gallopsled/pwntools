__all__ = ['PwnlibException']

class PwnlibException(Exception):
    def __init__(self, msg, reason = None, exit_code = None):
        Exception.__init__(self, msg)
        self.reason = reason
        self.exit_code = exit_code

    def __repr__(self):
        s = 'PwnlibException: %s' % self.message
        import traceback, sys
        if self.reason:
            s += '\nReason:\n'
            s += ''.join(traceback.format_exception(*self.reason))
        elif sys.exc_type not in [None, KeyboardInterrupt]:
            s += '\n'
            s += ''.join(traceback.format_exc())
        return s
