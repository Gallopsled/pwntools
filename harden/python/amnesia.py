from inspect import stack
from types import ModuleType

whitelist = open('whitelist').read().strip().split('\n')
whitelist = set(whitelist + ['__builtins__', 'excepthook', 'stderr', 'stdin', 'stdout', 'meta_path', 'path', 'path_hooks', 'path_importer_cache'])

if '__import__' in whitelist:
    base = open('python_standard').read().strip().split('\n')
    for b in base:
        try:
            __import__(b)
        except:
            pass

myglobals = globals()

seen = set()

def naptime(o):
    try:
        if o in seen:
            return
    except:
        try:
            for x in seen:
                if x == o:
                    return
        except:
            return
    try:
        seen.add(o)
    except:
        return
    if isinstance(o, ModuleType):
        for x in list(o.__dict__):
            if x not in whitelist:
                del o.__dict__[x]
            else:
                naptime(o)

for s in stack()[1:]:
    l = s[0].f_globals
    for x in list(l):
        if x not in whitelist:
            del l[x]
        else:
            naptime(l[x])

l = s[0].f_locals
for x in list(l):
    if x not in whitelist:
        del l[x]
    else:
        naptime(l[x])

l = __builtins__
for x in list(l):
    if x not in whitelist:
        del l[x]

for x in list(myglobals):
    if x not in ['x', 'myglobals', '__builtins__']:
        del myglobals[x]

del __builtins__
del x, myglobals
