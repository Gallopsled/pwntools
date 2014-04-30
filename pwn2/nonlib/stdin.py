__all__ = ['getkey', 'readline', 'prompt', 'file', 'pause', 'yesno', 'options']

import term, key

def getkey (timeout = None):
    return key.get(timeout)

if term.available:
    history = []

    def read_history ():
        # XXX: write this
        global history
        pass

    def write_history ():
        # XXX: write this
        pass

    import atexit
    atexit.register(write_history)

    # XXX: interface for auto-completion etc., plox

    def readline (size = None):
        from ..lib import text
        cursor = text.on_blue
        try:
            history.insert(0, [])
            histidx = 0
            s = []
            i = 0
            h = term.output()
            while True:
                if i == len(s):
                    t = ''.join(s) + cursor(' ')
                else:
                    t = ''.join(s[:i]) + cursor(s[i]) + ''.join(s[i+1:])
                h.update(t)
                k = getkey()
                if   k.type == key.TYPE_UNICODE and k.mods == key.MOD_NONE:
                    s = s[:i] + [k.code] + s[i:]
                    i += 1
                    history[0] = s
                    histidx = 0
                elif k.type == key.TYPE_KEYSYM:
                    if k.mods == key.MOD_NONE:
                        if   k.code == key.KEY_LEFT:
                            i = max(0, i - 1)
                        elif k.code == key.KEY_RIGHT:
                            i = min(len(s), i + 1)
                        elif k.code == key.KEY_UP:
                            if histidx < len(history) - 1:
                                histidx += 1
                                s = history[histidx]
                                i = len(s)
                        elif k.code == key.KEY_DOWN:
                            if histidx > 0:
                                histidx -= 1
                                s = history[histidx]
                                i = len(s)
                        elif k.code == key.KEY_DEL:
                            if i > 0:
                                s = s[:i - 1] + s[i:]
                                i -= 1
                                history[0] = s
                                histidx = 0
                        elif k.code == key.KEY_DELETE:
                            if i < len(s):
                                s = s[:i] + s[i + 1:]
                                history[0] = s
                                histidx = 0
                        elif k.code == key.KEY_ENTER:
                            break
                elif k.mods == key.MOD_CTRL and k.code == 'd' and s == []:
                    history.pop(0)
                    return ''
            history[0] = s
            return ''.join(s) + '\n'
        except:
            history.pop(0)
            raise
        finally:
            h.update(''.join(s) + '\n')
            h.freeze()

    def raw_input (prompt = ''):
        if prompt:
            term.output(prompt, frozen = True)
        return readline()

    import sys
    class Wrapper:
        def __init__ (self, fd):
            self._fd = fd
        def readline (self, size = None):
            return readline(size)
        def __getattr__ (self, k):
            return self._fd.__getattribute__(k)
    sys.stdin = Wrapper(sys.stdin)
