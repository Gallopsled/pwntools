try:
    base = long  # workaround for py2
except NameError:
    base = int

class Constant(base):
    def __new__(cls, s, i):
        obj = super(Constant, cls).__new__(cls, i)
        obj.s = s
        return obj
    def __str__(self):
        return self.s
    def __repr__(self):
        return 'Constant(%r, %#x)' % (self.s,int(self))
