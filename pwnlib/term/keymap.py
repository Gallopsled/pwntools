__all__ = ['Keymap']

from . import keyconsts as kc

class Matcher:
    def __init__(self, desc):
        self._desc = desc
        desc = desc.split('-')
        mods = desc[:-1]
        k = desc[-1]
        if k == '<space>':
            k = ' '
        m = kc.MOD_NONE
        if 'S' in mods:
            m |= kc.MOD_SHIFT
        if 'M' in mods:
            m |= kc.MOD_ALT
        if 'C' in mods:
            m |= kc.MOD_CTRL
        if   len(k) == 1:
            t = kc.TYPE_UNICODE
            c = k
            h = ord(k)
        elif k[0] == '<' and k in kc.KEY_NAMES_REVERSE:
            t = kc.TYPE_KEYSYM
            c = kc.KEY_NAMES_REVERSE[k]
            h = c
        elif k[:2] == '<f' and k[-1] == '>' and k[2:-1].isdigit():
            t = kc.TYPE_FUNCTION
            c = int(k[2:-1])
            h = c
        else:
            raise ValueError('bad key description "%s"' % k)
        self._type = t
        self._code = c
        self._mods = m
        self._hash = h | (m << 6) | (t << 7)

    def __call__(self, k):
        from . import key
        if isinstance(k, key.Key):
            return all([k.type == self._type,
                        k.code == self._code,
                        k.mods == self._mods,
                        ])

    def __eq__(self, other):
        from . import key
        if   isinstance(other, Matcher):
            return all([other._type == self._type,
                        other._code == self._code,
                        other._mods == self._mods,
                        ])
        elif isinstance(other, key.Key):
            return self.__call__(other)
        else:
            return False

    def __hash__(self):
        return self._hash

    def __str__(self):
        return self._desc

class Keymap:
    def __init__(self, bindings, on_match = None, on_nomatch = None,
                  on_key = None):
        self._on_match = on_match
        self._on_nomatch = on_nomatch
        self._on_key = on_key
        self._top = {}
        self._cur = self._top
        self.trace = []
        self.register(bindings)

    def handle_input(self):
        from . import key
        self._doread = True
        while self._doread:
            self.send(key.get())

    def stop(self):
        self._doread = False

    @property
    def currently_entered(self):
        return ' '.join(map(str, self.trace))

    def reset(self):
        self._cur = self._top
        self.trace = []

    def send(self, k):
        self.trace.append(k)
        if self._on_key:
            self._on_key(self.trace)
        match = False
        for m, (t, cbs) in self._cur.items():
            if m(k):
                self._cur = t
                if cbs:
                    match = True
                    if self._on_match:
                        self._on_match(self.trace)
                    for cb in cbs:
                        cb(self.trace)
        if not match and self._on_nomatch:
            self._on_nomatch(self.trace)
        tr = self.trace
        if len(self._cur) == 0 or not match:
            self.reset()
        if len(tr) > 1 and not match:
            self.send(k)

    def register(self, desc, cb = None):
        if isinstance(desc, dict):
            for k, v in desc.items():
                self.register(k, v)
        else:
            if   desc == '<match>':
                self.on_match(cb)
            elif desc == '<nomatch>':
                self.on_nomatch(cb)
            elif desc == '<any>':
                self.on_key(cb)
            else:
                ms = map(Matcher, desc.split(' '))
                if not ms:
                    return
                t = self._top
                for m in ms:
                    if m not in t:
                        t[m] = ({}, [])
                    t, cbs = t[m]
                cbs.append(cb)

    def unregister(self, desc, cb = None):
        ms = map(Matcher, desc.split(' '))
        if not ms:
            return
        t = self._top
        bt = []
        cbs = None
        for m in ms:
            if m not in t:
                return
            bt.append((t, cbs))
            t, cbs = t[m]
        if cb and cb in cbs:
            cbs.remove(cb)
        else:
            while True:
                try:
                    cbs.pop()
                except IndexError:
                    break
        # delete empty branch by backtracking
        while not t and not cbs:
            m = ms.pop()
            t, cbs = bt.pop()
            del t[m]

    def on_match(self, cb):
        self._on_match = cb

    def on_nomatch(self, cb):
        self._on_nomatch = cb

    def on_key(self, cb):
        self._on_key = cb
