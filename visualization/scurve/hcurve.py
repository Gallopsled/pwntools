import math

class Hcurve:
    """
        The H-curve, described in "Towards Optimal Locality in Mesh-Indexings"
        by R. Niedermeier , K. Reinhardt  and P. Sanders.

        This code is a straight transliteration of the implementation by
        Reinhard, found here:

            http://www2-fs.informatik.uni-tuebingen.de/~reinhard/hcurve.html
    """
    def __init__(self, dimension, size):
        """
            dimension: Number of dimensions
            size: The size in each dimension
        """
        if dimension != 2:
            raise ValueError("Invalid dimension - we can only draw the H-curve in 2 dimensions.")
        x = math.log(size, 2)
        if not float(x) == int(x):
            raise ValueError("Invalid size - has to be a power of 2.")
        self.dimension, self.size = int(dimension), int(size)

    @classmethod
    def fromSize(self, dimension, size):
        """
            size: total number of points in the curve.
        """
        x = math.ceil(math.pow(size, 1/float(dimension)))
        if not x**dimension == size:
            raise ValueError("Size does not fit a square Hcurve.")
        return Hcurve(dimension, int(x))

    def __len__(self):
        return self.size**self.dimension

    def dimensions(self):
        """
            Size of this curve in each dimension.
        """
        return [self.size]*self.dimension

    def __getitem__(self, idx):
        if idx >= len(self):
            raise IndexError
        return self.point(idx)

    def cor(self, d, i, n):
        # Size of this sub-triangle
        tsize = n**self.dimension/2
        if i < 0:
            return 0
        elif i < d + 1:
            return d
        elif i >= tsize:
            return n - self.cor(d, i - tsize, n) - 1
        else:
            # Which of the four sub-triangles of this triangle are we in?
            x = 4*i/tsize
            f = 1 if i+1 == d else 0
            if x == 0: return self.cor(d, i, n/2) 
            if x == 1: return self.cor(d, tsize/2 - 1 - i, n/2) - 0
            if x == 2: return n/2 - self.cor(d, 3 * tsize/4 - 1 - i, n/2) - 1
            if x == 3: return n/2 + self.cor(d, i - 3 * tsize/4, n/2) - 0

    def xcor(self, i, n):
        # Size of this sub-triangle
        tsize = n**self.dimension/2
        if i < 1:
            return 0
        elif i >= tsize:
            return n - self.xcor(i - tsize, n) - 1
        else:
            # Which of the four sub-triangles of this triangle are we in?
            x = 4*i/tsize
            f = 0
            if x == 0: return self.xcor(i, n/2)
            if x == 1: return self.xcor(tsize/2 - 1 - i, n/2)
            if x == 2: return n/2 - self.xcor(3 * tsize/4 - 1 - i, n/2) - 1
            if x == 3: return n/2 + self.xcor(i - 3 * tsize/4, n/2)
                
    def ycor(self, i, n):
        tsize = n**self.dimension/2
        if i < 2:
            return i
        elif i >= tsize:
            return n - self.ycor(i - tsize, n) - 1
        else:
            x = 4*i/tsize
            if x == 0: return self.ycor(i, n/2)
            if x == 1: return n - self.ycor(tsize/2 - 1 - i, n/2) - 1
            if x == 2: return n/2 + self.ycor(3 * tsize/4 - 1 - i, n/2)
            if x == 3: return n/2 + self.ycor(i - 3 * tsize/4, n/2)

    def point(self, idx):
        return [self.cor(0, idx, self.size), self.ycor(idx, self.size)]

