import threading

def _async_raise(tid, exc):
    import ctypes, types
    if type(exc) != types.TypeType:
        raise TypeError('exception must be a type (vs. instance)')
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(tid),
        ctypes.py_object(exc)
        )
    if res == 0:
        raise ValueError('invalid thread id')
    if res > 1:
        # must reset exception in affected threads
        ctypes.pythonapi.PyThreadState_SetAsyncExc(
            ctypes.c_long(tid),
            ctypes.c_voidp(0)
            )
        raise SystemError('PyThreadState_SetAsyncExc failed')

class Thread(threading.Thread):
    def raise_exc(self, exc):
        _async_raise(self.ident, exc)

    def sigterm(self):
        self.raise_exc(SystemExit)

    def terminate(self):
        try:
            self.sigterm()
            self.join()
        except:
            pass
