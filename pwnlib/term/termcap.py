__all__ = ['get']

cache = None
def get(cap, *args):
    if cache == None:
        init()
    s = cache.get(cap)
    if not s:
        s = curses.tigetstr(cap) or ''
        cache[cap] = s
    if args:
        return curses.tparm(s, *args)
    else:
        return s

def init():
    global curses, cache
    import curses
    curses.setupterm()

    cache = {}
