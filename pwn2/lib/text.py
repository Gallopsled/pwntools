import types, sys, pwn2

# somewhat arbitrary to look at stderr, but that's what the log module uses
if pwn2.hasterm or sys.stderr.isatty():
    class Module(types.ModuleType):
        def __init__ (self):
            import curses, os
            self.__file__ = __file__
            self.__name__ = __name__
            self._capcache = {}
            self._curses = curses
            curses.setupterm()
            self.num_colors = self._cap('colors')
            self.has_bright = self.num_colors >= 16
            self.has_gray = self.has_bright
            self._colors = {
                'black': 0,
                'red': 1,
                'green': 2,
                'yellow': 3,
                'blue': 4,
                'magenta': 5,
                'cyan': 6,
                'white': 7,
                }
            self._reset = '\x1b[m'
            self._attributes = {}
            for d in ['italic', 'bold', 'underline']:
                s = self._cap(d)
                if s:
                    self._attributes[d] = s

        def _cap (self, c):
            s = self._capcache.get(c)
            if s:
                return s
            s = self._curses.tigetstr(c) or ''
            self._capcache[c] = s
            return s

        def _fg_color (self, c):
            return self._curses.tparm(self._cap('setaf') or self._cap('setf'),
                                      c)

        def _bg_color (self, c):
            return self._curses.tparm(self._cap('setab') or self._cap('setb'),
                                      c)

        def _decorator (self, name, init):
            def f (s):
                return init + s + self._reset
            setattr(self, name, f)
            return f

        def __getattr__ (self, desc):
            ds = desc.replace('gray', 'bright_black').split('_')
            init = ''
            while True:
                d = ds[0]
                try:
                    init += self._attributes[d]
                    ds.pop(0)
                except:
                    break
            def c():
                bright = 0
                c = ds.pop(0)
                if c == 'bright':
                    c = ds.pop(0)
                    if self.has_bright:
                        bright = 8
                return self._colors[c] + bright

            if ds:
                if ds[0] == 'on':
                    ds.pop(0)
                    init += self._bg_color(c())
                else:
                    init += self._fg_color(c())
                    if len(ds):
                        assert ds.pop(0) == 'on'
                        init += self._bg_color(c())
            return self._decorator(desc, init)

        def get(self, desc):
            return self.__getattr__(desc)
else:
    class Module(types.ModuleType):
        def __init__ (self):
            self.num_colors = 0
            self.has_bright = False
            self.has_gray = False

        def __getattr__ (self, _):
            return lambda x: x

if __name__ <> '__main__':
    sys.modules[__name__] = Module()
