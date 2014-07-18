import types, sys
from . import termcap

# somewhat arbitrary to look at stdout, but that's what the log module uses
if sys.stdout.isatty():
    class Module(types.ModuleType):
        def __init__(self):
            self.__file__ = __file__
            self.__name__ = __name__
            self.num_colors = termcap.get('colors', default = 8)
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
            for x, y in [('italic'   , 'sitm'),
                         ('bold'     , 'bold'),
                         ('underline', 'smul'),
                         ('reverse'  , 'rev')]:
                s = termcap.get(y)
                self._attributes[x] = s

        def _fg_color(self, c):
            return termcap.get('setaf', c) or self._tc.get('setf', c)

        def _bg_color(self, c):
            return termcap.get('setab', c) or self._tc.get('setb', c)

        def _decorator(self, name, init):
            def f(s):
                return init + s + self._reset
            setattr(self, name, f)
            return f

        def __getattr__(self, desc):
            ds = desc.replace('gray', 'bright_black').split('_')
            init = ''
            while ds:
                d = ds[0]
                try:
                    init += self._attributes[d]
                    ds.pop(0)
                except KeyError:
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
        def __init__(self):
            self.num_colors = 0
            self.has_bright = False
            self.has_gray = False

        def __getattr__(self, _):
            return lambda x: x

tether = sys.modules[__name__]
sys.modules[__name__] = Module()
