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
        s = curses.tigetstr(cap)
        if s == None:
            s = curses.tigetnum(cap)
            if s == -2:
                s = curses.tigetflag(cap)
                if s == -1:
                    # default to empty string so tparm doesn't fail
                    s = ''
                else:
                    s = bool(s)
        cache[cap] = s
    if args:
        return curses.tparm(s, *args)
    else:
        return s

def init():
    global cache
    curses.setupterm()

    cache = {}
