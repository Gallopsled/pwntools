from pwn import ciic

_code = '''

#define SIDE #SIDE#

void rot(int n, int *x, int *y, int rx, int ry) {
  if (ry == 0) {
    if (rx == 1) {
      *x = n-1 - *x;
      *y = n-1 - *y;
    }

  int t  = *x;
  *x = *y;
  *y = t;
  }
}

int encode (int p) {
  int x, y, rx, ry, s, d=0;
  x = p & 0xffff;
  y = p >> 16;
  for (s=SIDE/2; s>0; s/=2) {
    rx = (x & s) > 0;
    ry = (y & s) > 0;
    d += s * s * ((3 * rx) ^ ry);
    rot(s, &x, &y, rx, ry);
  }
  return d;
}

int decode (int d) {
  int x=0, y=0, rx, ry, s, t=d;
  for (s=1; s<SIDE; s*=2) {
    rx = 1 & (t/2);
    ry = 1 & (t ^ rx);
    rot(s, &x, &y, rx, ry);
    x += s * rx;
    y += s * ry;
    t /= 4;
  }
  return x | (y << 16);
}
'''

class Hilbert:
    def __init__ (self, size):
        o = 0
        while True:
            if 2**(o*2) >= size:
                break
            o += 1
        self.order = o
        self.area = 2**(o*2)
        self.side = 2**o
        self.dll = ciic(_code.replace('#SIDE#', str(2**self.order)))

    def encode(self, (x, y)):
        return self.dll.encode(x | (y << 16))

    def decode(self, d):
        p = self.dll.decode(d)
        return (p & 0xffff, p >> 16)

# h = Hilbert(65)
# print h.area, h.side, h.order
# for d in range(2**4):
#     print d, h.decode(d)
