import math

class ZigZag:
    """
        An n-dimensional zig-zag curve - it snakes through the n-cube, with
        each point differing from the previous point by exactly one. Not
        useful, but it's a good counterpoint to other space-filling curves.
    """
    def __init__(self, dimension, size):
        """
            dimension: Number of dimensions
            size: The size in each dimension
        """
        self.dimension, self.size = int(dimension), int(size)

    @classmethod
    def fromSize(self, dimension, size):
        """
            size: total number of points in the curve.
        """
        x = math.ceil(math.pow(size, 1/float(dimension)))
        if not x**dimension == size:
            raise ValueError("Size does not fit a square ZigZag curve.")
        return ZigZag(dimension, int(x))

    def __len__(self):
        return self.size**self.dimension

    def __getitem__(self, idx):
        if idx >= len(self):
            raise IndexError
        return self.point(idx)

    def dimensions(self):
        """
            Size of this curve in each dimension.
        """
        return [self.size]*self.dimension

    def index(self, p):
        idx = 0
        flip = False
        for power, i in enumerate(reversed(list(p))):
            power = self.dimension-power-1
            if flip:
                fi = self.size-i-1
            else:
                fi = i
            v = fi * (self.size**power)
            idx += v
            if i%2:
                flip = not flip
        return idx

    def point(self, idx):
        p = []
        flip = False
        for i in range(self.dimension-1, -1, -1):
            v = idx/(self.size**i)
            if i > 0:
                idx = idx - (self.size**i)*v
            if flip:
                v = self.size-1-v
            p.append(v)
            if v%2:
                flip = not flip
        return reversed(p)
