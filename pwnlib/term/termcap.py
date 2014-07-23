__all__ = ['get']
import curses

cache = None
def get(cap, *args, **kwargs):
    default = kwargs.pop('default', '')

    if kwargs != {}:
        raise TypeError("get(): No such argument %r" % kwargs.popitem()[0])

    if cache == None:
        init()
    s = cache.get(cap)
    if not s:
        s = curses.tigetstr(cap) or default
        cache[cap] = s
    if args:
        return curses.tparm(s, *args)
    else:
        return s

def init():
    global cache
    curses.setupterm()

    cache = {}
