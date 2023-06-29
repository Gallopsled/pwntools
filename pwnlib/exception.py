__all__ = ['PwnlibException']
import sys
import traceback


class PwnlibException(Exception):
    '''Exception thrown by :func:`pwnlib.log.error`.

    Pwnlib functions that encounters unrecoverable errors should call the
    :func:`pwnlib.log.error` function instead of throwing this exception directly.'''
    def __init__(self, msg, reason = None, exit_code = None):
        '''bar'''
        Exception.__init__(self, msg)
        self.reason = reason
        self.exit_code = exit_code
        self.message = msg

    def __repr__(self):
        s = 'PwnlibException: %s' % self.message
        if self.reason:
            s += '\nReason:\n'
            s += ''.join(traceback.format_exception(*self.reason))
        elif sys.exc_info()[0] not in [None, KeyboardInterrupt]:
            s += '\n'
            s += ''.join(traceback.format_exc())
        return s
