import utils, math


def transform(entry, direction, width, x):
    assert x < 2**width
    assert entry < 2**width
    return utils.rrot((x^entry), direction+1, width)


def itransform(entry, direction, width, x):
    """
        Inverse transform - we simply reverse the operations in transform.
    """
    assert x < 2**width
    assert entry < 2**width
    return utils.lrot(x, direction+1, width)^entry
    # There is an error in the Hamilton paper's formulation of the inverse
    # transform in Lemma 2.12. The correct restatement as a transform is as follows:
    #return transform(rrot(entry, direction+1, width), width-direction-2, width, x)


def direction(x, n):
    assert x < 2**n
    if x == 0:
        return 0
    elif x%2 == 0:
        return utils.tsb(x-1, n)%n
    else:
        return utils.tsb(x, n)%n


def entry(x):
    if x == 0:
        return 0
    else:
        return utils.graycode(2*((x-1)/2))


def hilbert_point(dimension, order, h):
    """
        Convert an index on the Hilbert curve of the specified dimension and
        order to a set of point coordinates.
    """
    #    The bit widths in this function are:
    #        p[*]  - order
    #        h     - order*dimension
    #        l     - dimension
    #        e     - dimension
    hwidth = order*dimension
    e, d = 0, 0
    p = [0]*dimension
    for i in range(order):
        w = utils.bitrange(h, hwidth, i*dimension, i*dimension+dimension)
        l = utils.graycode(w)
        l = itransform(e, d, dimension, l)
        for j in range(dimension):
            b = utils.bitrange(l, dimension, j, j+1)
            p[j] = utils.setbit(p[j], order, i, b)
        e = e ^ utils.lrot(entry(w), d+1, dimension)
        d = (d + direction(w, dimension) + 1)%dimension
    return p


def hilbert_index(dimension, order, p):
    h, e, d = 0, 0, 0
    for i in range(order):
        l = 0
        for x in range(dimension):
            b = utils.bitrange(p[dimension-x-1], order, i, i+1)
            l |= b<<x
        l = transform(e, d, dimension, l)
        w = utils.igraycode(l)
        e = e ^ utils.lrot(entry(w), d+1, dimension)
        d = (d + direction(w, dimension) + 1)%dimension
        h = (h<<dimension)|w
    return h


class Hilbert:
    def __init__(self, dimension, order):
        self.dimension, self.order = dimension, order

    @classmethod
    def fromSize(self, dimension, size):
        """
            Size is the total number of points in the curve.
        """
        x = math.log(size, 2)
        if not float(x)/dimension == int(x)/dimension:
            raise ValueError("Size does not fit Hilbert curve of dimension %s."%dimension)
        return Hilbert(dimension, int(x/dimension))

    def __len__(self):
        return 2**(self.dimension*self.order)

    def __getitem__(self, idx):
        if idx >= len(self):
            raise IndexError
        return self.point(idx)

    def dimensions(self):
        """
            Size of this curve in each dimension.
        """
        return [int(math.ceil(len(self)**(1/float(self.dimension))))]*self.dimension

    def index(self, p):
        return hilbert_index(self.dimension, self.order, p)

    def point(self, idx):
        return hilbert_point(self.dimension, self.order, idx)

