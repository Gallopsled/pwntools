import pwn, math, inspect

def _tobits(s):
    return pwn.bits(s, endian = 'little')

def _frombits(b):
    return pwn.unbits(b, endian = 'little')

def _btoi(bits):
    x = 0
    for b in bits[::-1]:
        x <<= 1
        x += b
    return x

def _itob(x):
    bits = []
    while x <> 0:
        bits.insert(0, x & 1)
        x >>= 1
    return bits

def _bitsum(x):
    s = 0
    while x:
        s ^= x & 1
        x >>= 1
    return s

def _reverse_box(box):
    inv = [None] * len(box)
    try:
        for x in range(len(box)):
            y = box[x]
            inv[y] = x
    except:
        raise ValueError('Box has different domain and co-domain')
    if None in inv:
        raise ValueError('Box is not reversable')
    return inv

@pwn.memoize
def linear_table(sbox):
    n = len(sbox)
    tbl = [[0 for i in range(n)] for j in range(n)]
    for i in range(n):
        for o in range(n):
            for x in range(n):
                y = sbox[x]
                if _bitsum(x & i) == _bitsum(y & o):
                    tbl[i][o] += 1
    tbl[0][0]
    for i in range(n):
        for o in range(n):
            tbl[i][o] = abs(tbl[i][o]) / (2.0 * n)
    return tbl

def differential_table(sbox):
    pass

class SBoxes:
    def __init__ (self, *boxes):
        if isinstance(boxes[0], int):
            rep = boxes[0]
            boxes = list(boxes[1:])
            boxes = boxes * rep
        self.blocksize = 0
        self.boxes = []
        for box in boxes:
            size = int(math.log(len(box), 2))
            if 2**size <> len(box):
                raise ValueError('S-box must have 2**n entries')
            self.blocksize += size
            self.boxes.append((size, box, _reverse_box(box)))

    def _substitute(self, block, boxes):
        nextblock = []
        for size, box in boxes:
            ibits = block[:size]
            block = block[size:]
            if None in ibits:
                obits = [None] * size
            else:
                obits = _itob(box[_btoi(ibits)])
            obits += [0] * (len(ibits) - len(obits))
            nextblock += obits
        return nextblock

    def forward(self, block):
        return self._substitute(block, ((s, b) for s, b, _ in self.boxes))

    def backward(self, block):
        return self._substitute(block, ((s, b) for s, _, b in self.boxes))

class PBox:
    def __init__ (self, pbox):
        self.blocksize = len(pbox)
        self.pbox = pbox
        self.inv_pbox = _reverse_box(pbox)

    def forward (self, block):
        return [block[self.inv_pbox[i]] for i in range(self.blocksize)]

    def forward (self, block):
        return [block[self.pbox[i]] for i in range(self.blocksize)]

class KMix:
    def __init__ (self, *args):
        self.blocksize = None
        self.subkey = None

class KMixXor(KMix):
    def __init__ (self, *args):
        KMix.__init__(self)

    def forward (self, x):
        y = []
        k = self.subkey
        for a, b in zip(k, x):
            if a is None or b is None:
                y.append(None)
            else:
                y.append(a ^ b)
        return y

    def backward (self, x):
        return self.forward(x)

class SPN:
    def __init__ (self, *layers, **kwargs):
        self.blocksize = kwargs.get('blocksize', None)
        layers = list(layers)
        for l in layers:
            if isinstance(l, SBoxes) or isinstance(l, PBox):
                self.blocksize = l.blocksize
                break
        if self.blocksize is None:
            raise ValueError('Could not determine block size from SPN layers')
        for i in range(len(layers)):
            l = layers[i]
            if inspect.isclass(l):
                l = l()
                layers[i] = l
            if isinstance(l, KMix):
                l.blocksize = self.blocksize
                l.subkey = [None] * self.blocksize
            elif l.blocksize <> self.blocksize:
                raise ValueError(
                    'Blocksize %d of layer %d(%s) in SPN does not match (should be %d)' \
                    % (l.blocksize, i, l.__class__, self.blocksize))
        self.layers = layers
        self.slayers = []
        self.players = []
        self.klayers = []
        for l in layers:
            if   isinstance(l, SBoxes):
                self.slayers.append(l)
            elif isinstance(l, PBox):
                self.players.append(l)
            elif isinstance(l, KMix):
                self.klayers.append(l)

    def clearKeys(self):
        for k in self.klayers:
            k.subkey = [0] * self.blocksize

    def setKeys(self, *subkeys):
        subkeys = list(subkeys)
        if len(subkeys) == 1:
            key = subkeys[0]
            if isinstance(key, str):
                key = _tobits(key)
            subkeys = pwn.group(key, self.blocksize)
        for i in range(len(subkeys)):
            if isinstance(subkeys[i], str):
                subkeys[i] = _tobits(subkeys[i])
            if len(subkeys[i]) <> self.blocksize:
                raise ValueError('Wrong subkey size')
        for kmix, k in zip(self.klayers, subkeys):
            kmix.subkey = k

    def encrypt(self, block, visualize = True, endian = 'little'):
        block = _tobits(block)
        log = ''
        for i in range(len(self.layers)):
            l = self.layers[i]
            log += '%2d ' % i
            log += ''.join(' ' if b is None else str(b) for b in block)
            if   isinstance(l, SBoxes):
                log += ' -> S'
            elif isinstance(l, PBox):
                log += ' -> P'
            elif isinstance(l, KMix):
                log += ' -> K'
            log += '\n'
            block = l.forward(block)
        log += '%2d ' % len(self.layers)
        log += ''.join(' ' if b is None else str(b) for b in block)
        tens = '   ' + ''.join(str(i / 10).ljust(10) for i in range(0, self.blocksize, 10))
        ones = '   ' + ''.join(str(i)[-1] for i in range(self.blocksize))
        header = ones + '\n' + tens
        footer = tens + '\n' + ones
        log = header + '\n' + log + '\n' + footer
        if visualize: print log
        return None if None in block else _frombits(block)
