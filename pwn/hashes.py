import hashlib

for _algo in hashlib.algorithms:
    def _closure():
        hash = hashlib.__dict__[_algo]
        def file(p):
            h = hash()
            fd = open(p)
            while True:
                s = fd.read(4096)
                if not s: break
                h.update(s)
            fd.close()
            return h
        def sum(s):
            return hash(s)
        file = lambda x: file(x).digest()
        file.__doc__ = 'Calculates the %s sum of a file' % _algo
        sum = lambda x: sum(x).digest()
        sum.__doc__ = 'Calculates the %s sum of a string' % _algo
        fileh = lambda x: file(x).hexdigest()
        fileh.__doc__ = 'Calculates the %s sum of a file; returns hex-encoded' % _algo
        sumh = lambda x: sum(x).hexdigest()
        sumh.__doc__ = 'Calculates the %s sum of a string; returns hex-encoded' % _algo
        return file, sum, fileh, sumh
    file, sum, filehex, sumhex = _closure()
    globals()[_algo + 'file'] = file
    globals()[_algo + 'sum'] = sum
    globals()[_algo + 'filehex'] = filehex
    globals()[_algo + 'sumhex'] = sumhex
