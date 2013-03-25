import math

class Natural:
    """
        A natural order traversal of the points in a cube. Each point is
        simply considered a digit in a number.
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
            raise ValueError("Size does not fit a square curve.")
        return Natural(dimension, math.ceil(x))

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
        for power, i in enumerate(p):
            power = self.dimension-power-1
            idx += i * (self.size**power)
        return idx

    def point(self, idx):
        p = []
        for i in range(self.dimension-1, -1, -1):
            v = idx/(self.size**i)
            if i > 0:
                idx = idx - (self.size**i)*v
            p.append(v)
        return p
