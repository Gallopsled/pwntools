__all__ = ['Keymap', 'KEYMAP_AGAIN', 'KEYMAP_MATCH', 'KEYMAP_NOMATCH']

import key, types, struct

class Matcher:
    def __init__ (self, desc):
        self._desc = desc
        desc = desc.split('-')
        mods = desc[:-1]
        k = desc[-1]
        if k == '<space>':
            k = ' '
        m = key.MOD_NONE
        if 'S' in mods:
            m |= key.MOD_SHIFT
        if 'M' in mods:
            m |= key.MOD_ALT
        if 'C' in mods:
            m |= key.MOD_CTRL
        if   len(k) == 1:
            t = key.TYPE_UNICODE
            c = k
            h = struct.unpack('Q', k.ljust(8))[0]
        elif k[0] == '<' and k in key.KEY_NAMES_REVERSE:
            t = key.TYPE_KEYSYM
            c = key.KEY_NAMES_REVERSE[k]
            h = c
        elif k[:2] == '<f' and k[-1] == '>' and k[2:-1].isdigit():
            t = key.TYPE_FUNCTION
            c = int(k[2:-1])
            h = c
        else:
            raise ValueError('bad key description "%s"' % k)
        self._type = t
        self._code = c
        self._mods = m
        self._hash = h | (m << 6) | (t << 7)

    def __call__ (self, k):
        return all([k.type == self._type,
                    k.code == self._code,
                    k.mods == self._mods,
                    ])

    def __eq__ (self, other):
        return all([other._type == self._type,
                    other._code == self._code,
                    other._mods == self._mods,
                    ])

    def __hash__ (self):
        return self._hash

    def __str__ (self):
        return self._desc

KEYMAP_AGAIN, KEYMAP_MATCH, KEYMAP_NOMATCH = range(3)

class Keymap:
    def __init__ (self, bindings, on_nomatch = None):
        self._on_nomatch = on_nomatch
        self._top = {}
        self._cur = self._top
        self.trace = []
        self.register(bindings)

    def handle_input (self):
        import key
        self._doread = True
        while self._doread:
            self.send(key.get())

    def stop (self):
        self._doread = False

    @property
    def currently_entered (self):
        return ' '.join(map(str, self.trace))

    def reset (self):
        self._cur = self._top
        self.trace = []

    def send (self, k):
        self.trace.append(k)
        # we're in a submap
        if isinstance(self._cur, Keymap):
            ret = self._cur.send(k)
            if ret == KEYMAP_NOMATCH and self._on_nomatch:
                self._on_nomatch(self.trace)
            if ret <> KEYMAP_AGAIN:
                self.reset()
            return ret
        # not in a submap
        for m, t in self._cur.items():
            if m(k):
                if isinstance(t, tuple):
                    v, = t
                    if isinstance(v, types.FunctionType):
                        v(self.trace)
                    elif isinstance(v, Keymap):
                        self._cur = v
                        return KEYMAP_AGAIN
                    self.reset()
                    return KEYMAP_MATCH
                else:
                    self._cur = t
                    return KEYMAP_AGAIN
        if self._on_nomatch:
            self._on_nomatch(self.trace)
        self.reset()
        return KEYMAP_NOMATCH

    def register (self, desc, v = None):
        if isinstance(desc, dict):
            if 'nomatch' in desc:
                self.on_nomatch(desc['nomatch'])
                del desc['nomatch']
            for k, v in desc.items():
                self.register(k, v)
        else:
            ms = map(Matcher, desc.split(' '))
            if not ms:
                return
            t = self._top
            for m in ms[:-1]:
                if m not in t or not isinstance(t[m], dict):
                    t[m] = {}
                t = t[m]
            m = ms[-1]
            t[m] = (v, )

    def unregister (self, desc):
        ms = map(Matcher, desc.split(' '))
        if not ms:
            return
        t = self._top
        for m in ms[:-1]:
            if m not in t:
                return
            if len(t) == 1:
                del t[m]
                return
        m = ms[-1]
        if m in t:
            del t[m]

    def on_nomatch (self, cb):
        self._on_nomatch = cb
