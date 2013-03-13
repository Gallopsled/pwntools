#!/usr/bin/env python
import os.path, math, string, sys
import scurve
from scurve import progress, utils, draw
import Image, ImageDraw


class _Color:
    def __init__(self, data, block):
        self.data, self.block = data, block
        s = list(set(data))
        s.sort()
        self.symbol_map = {v : i for (i, v) in enumerate(s)}

    def __len__(self):
        return len(self.data)

    def point(self, x):
        if self.block and (self.block[0]<=x<self.block[1]):
            return self.block[2]
        else:
            return self.getPoint(x)


class ColorGradient(_Color):
    def getPoint(self, x):
        c = ord(self.data[x])/255.0
        return [
            int(255*c),
            int(255*c),
            int(255*c)
        ]


class ColorHilbert(_Color):
    def __init__(self, data, block):
        _Color.__init__(self, data, block)
        self.csource = scurve.fromSize("hilbert", 3, 256**3)
        self.step = len(self.csource)/float(len(self.symbol_map))

    def getPoint(self, x):
        c = self.symbol_map[self.data[x]]
        return self.csource.point(int(c*self.step))


class ColorClass(_Color):
    def getPoint(self, x):
        c = ord(self.data[x])
        if c == 0:
            return [0, 0, 0]
        elif c == 255:
            return [255, 255, 255]
        elif chr(c) in string.printable:
            return [55, 126, 184]
        return [228, 26, 28]


class ColorEntropy(_Color):
    def getPoint(self, x):
        e = utils.entropy(self.data, 256, x, len(self.symbol_map))
        # http://www.wolframalpha.com/input/?i=plot+%284%28x-0.5%29-4%28x-0.5%29**2%29**4+from+0.5+to+1
        def curve(v):
            f = (4*v - 4*v**2)**4
            f = max(f, 0)
            return f
        r = curve(e-0.5) if e > 0.5 else 0
        b = e**2
        return [
            int(255*r),
            0,
            int(255*b)
        ]


def drawmap_unrolled(map, size, csource, name, prog):
    prog.set_target((size**2)*4)
    map = scurve.fromSize(map, 2, size**2)
    c = Image.new("RGB", (size, size*4))
    cd = ImageDraw.Draw(c)
    step = len(csource)/float(len(map)*4)

    sofar = 0
    for quad in range(4):
        for i, p in enumerate(map):
            off = (i + (quad * size**2))
            color = csource.point(
                        int(off * step)
                    )
            x, y = tuple(p)
            cd.point(
                (x, y + (size * quad)),
                fill=tuple(color)
            )
            if not sofar%100:
                prog.tick(sofar)
            sofar += 1
    c.save(name)


def drawmap_square(map, size, csource, name, prog):
    prog.set_target((size**2))
    map = scurve.fromSize(map, 2, size**2)
    c = Image.new("RGB", map.dimensions())
    cd = ImageDraw.Draw(c)
    step = len(csource)/float(len(map))
    for i, p in enumerate(map):
        color = csource.point(int(i*step))
        cd.point(tuple(p), fill=tuple(color))
        if not i%100:
            prog.tick(i)
    c.save(name)


def main():
    from optparse import OptionParser, OptionGroup
    parser = OptionParser(
                usage = "%prog [options] infile [output]",
                version="%prog 0.1",
            )
    parser.add_option(
        "-b", "--block", action="store",
        dest="block", default=None,
        help="Mark a block of data with a specified color. Format: hexstartaddr:hexendaddr[:hexcolor]"
    )
    parser.add_option(
        "-c", "--color", action="store",
        type="choice", dest="color", default="class",
        choices=["class", "hilbert", "entropy", "gradient"],
        help="Color map."
    )
    parser.add_option(
        "-m", "--map", action="store",
        type="choice", dest="map", default="hilbert",
        choices=sorted(scurve.curveMap.keys()),
        help="Pixel layout map. Can be any supported curve."
    )
    parser.add_option(
        "-n", "--namesuffix", action="store",
        type="str", dest="suffix", default="",
        help="Suffix for generated file names. Ignored if destination is specified."
    )
    parser.add_option(
        "-p", "--progress", action="store_true", default=False,
        dest="progress",
        help="Don't show progress bar - print the destination file name."
    )
    parser.add_option(
        "-s", "--size", action="store",
        type="int", dest="size", default=256,
        help="Image width in pixels."
    )
    parser.add_option(
        "-t", "--type", type="choice",
        dest="type", default="unrolled",
        choices=["unrolled", "square"],
        help="Image aspect ratio - square (1x1) or unrolled (1x4)"
    )
    parser.add_option(
        "-q", "--quiet", action="store_true",
        dest="quiet", default=False
    )
    options, args = parser.parse_args()
    if len(args) not in [1, 2]:
        parser.error("Please specify input and output file.")

    d = file(args[0]).read()
    if len(args) == 2:
        dst = args[1]
    else:
        base = os.path.basename(args[0])
        if "." in base:
            base, _ = base.rsplit(".", 1)
        dst = base + options.suffix + ".png"

    if os.path.exists(dst) and len(args) < 2:
        print >> sys.stderr, "Refusing to over-write '%s'. Specify explicitly if you really want to do this."%dst
        sys.exit(1)

    block = None
    if options.block:
        parts = options.block.split(":")
        if len(parts) not in [2, 3]:
            raise ValueError("Invalid block specification.")
        s, e = int(parts[0], 16), int(parts[1], 16)
        if len(parts) == 3:
            c = draw.parseColor(parts[2])
        else:
            c = [255, 0, 0]
        block = (s, e, c)

    if options.color == "class":
        csource = ColorClass(d, block)
    elif options.color == "hilbert":
        csource = ColorHilbert(d, block)
    elif options.color == "gradient":
        csource = ColorGradient(d, block)
    else:
        csource = ColorEntropy(d, block)


    if options.progress:
        print dst

    if options.quiet or options.progress:
        prog = progress.Dummy()
    else:
        prog = progress.Progress(None)


    if options.type == "unrolled":
        drawmap_unrolled(options.map, options.size, csource, dst, prog)
    elif options.type == "square":
        drawmap_square(options.map, options.size, csource, dst, prog)
    prog.clear()


main()
