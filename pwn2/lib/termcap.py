__all__ = ['get']

import curses
curses.setupterm()

cache = {}
def get(cap, *args):
    s = cache.get(cap)
    if not s:
        s = curses.tigetstr(cap) or ''
        cache[cap] = s
    if args:
        return curses.tparm(s, *args)
    else:
        return s
