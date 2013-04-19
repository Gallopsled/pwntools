
from hilbert import HilbertCurve
# import hilbert_api as hapi
import pygame, sys
from PIL import Image
# pygame.init()
from pwn import log
import Image, ImageDraw
import scurve

GRID_SIZE_X = 32 # bytes == pixels?
GRID_SIZE_Y = 32
BG_COLOR = (0,0,0)

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

class ColorHilbert(_Color):
    def __init__(self, data, block):
        _Color.__init__(self, data, block)
        self.csource = scurve.fromSize("hilbert", 3, 256**3)
        self.step = len(self.csource)/float(len(self.symbol_map))

    def getPoint(self, x):
        c = self.symbol_map[self.data[x]]
        return self.csource.point(int(c*self.step))

def drawmap_square(map, size, csource):
    # prog.set_target((size**2))
    map = scurve.fromSize(map, 2, size**2)
    c = Image.new("RGB", map.dimensions())
    cd = ImageDraw.Draw(c)
    step = len(csource)/float(len(map))
    for i, p in enumerate(map):
        color = csource.point(int(i*step))
        cd.point(tuple(p), fill=tuple(color))
        # if not i%100:
        #     prog.tick(i)
    # c.save(name)
    return c, cd


class Visual(object):
    def __init__(self, target):
        self.target = target
        self.hilbertcurve = HilbertCurve(self.target)
        log.waitfor("Building square Hilbert image in memory")
        d = open(self.target).read()
        csource = ColorHilbert(d, None)
        self.image, self.cd = drawmap_square('hilbert', 256, csource)
        log.succeeded()
        # pygame.init()


    def doit(self):
        self.setup()
        self.mainLoop()


    def mainLoop(self): # , screen, px    ):
        SNAP_TO_GRID_TOPLEFT = SNAP_TO_GRID_BOTTOMRIGHT = SELECTION = None
        n=0
        scale = 1
        pos = [0,0]
        while 1:
            SNAP_TO_GRID_STOPIT = False
            event = pygame.event.wait() # just get a single event, idle until it comes... this lowered %CPU from around 80-100 to around 1-10

            if event.type == pygame.MOUSEBUTTONUP:
                mods = pygame.key.get_mods()
                if mods & pygame.KMOD_CTRL: # CTRL-LeftClick -> snap to grid selection
                    if not SNAP_TO_GRID_TOPLEFT:
                        SNAP_TO_GRID_TOPLEFT = self.snap_it(event.pos)
                    else:
                        SNAP_TO_GRID_BOTTOMRIGHT = event.pos
                        SNAP_TO_GRID_STOPIT = True
                else:
                    pass # these key-combinations should select based on the underlying graph (hilbert/entropy/etc)

            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_s:
                    if SELECTION:
                        print "--saving coordinates-- topleft: (%s,%s), width: %s, height: %s" % SELECTION
                        print "topleft: %s, %s" % (SELECTION[0], SELECTION[1])
                        print "bottomright: %s, %s" % (SELECTION[2] + SELECTION[0], SELECTION[3] + SELECTION[1])
                if event.key == pygame.K_d:
                    mods = pygame.key.get_mods()
                    if mods & pygame.KMOD_CTRL:
                        print "ctrl-d :D"

            if SNAP_TO_GRID_TOPLEFT:
                SELECTION = self.displayImage(SNAP_TO_GRID_TOPLEFT, SELECTION)
            if SNAP_TO_GRID_STOPIT:
                SNAP_TO_GRID_TOPLEFT = SNAP_TO_GRID_BOTTOMRIGHT = None
        return


    # @staticmethod
    # def setup(path):
    #     px = pygame.image.load(path)
    #     screen = pygame.display.set_mode( px.get_rect()[2:] )
    #     screen.blit(px, px.get_rect())
    #     pygame.display.flip()
    #     return screen, px

    def setup(self):
        ''' sets up the pygame screen, working with an image from memory (PIL.image) instead of loading from a file.
'''
        mode = self.image.mode
        size = self.image.size
        data = self.image.tostring()
        assert mode in "RGB", "RGBA"
        self.px = pygame.image.fromstring(data, size, mode)
        self.screen = pygame.display.set_mode( self.px.get_rect()[2:] )
        self.screen.blit(self.px, self.px.get_rect())
        pygame.display.flip()
        # return screen, px


    def displayImage(self, topleft, prior):
        # ensure that the rect always has positive width, height
        x, y = topleft
        mouse_pos = pygame.mouse.get_pos()
        width, height = self.snap_it((mouse_pos[0] - topleft[0], mouse_pos[1] - topleft[1]))
        # if height not in [0, 1]:
        #     width = px.get_rect()[3]
        #     x = 0

        if width < 0:
            x += width
            width = abs(width)
        if height < 0:
            y += height
            height = abs(height)

        # eliminate redundant drawing cycles (when mouse isn't moving)
        current = x, y, width, height
        if not (width and height):
            return current
        if current == prior:
            return current

        # draw transparent box and blit it onto canvas
        self.screen.blit(self.px, self.px.get_rect())
        im = pygame.Surface((width, height))
        im.fill((128, 128, 128))
        pygame.draw.rect(im, (32, 32, 32), im.get_rect(), 1)
        im.set_alpha(128)
        self.screen.blit(im, (x, y))
        pygame.display.flip()

        # return current box extents
        return (x, y, width, height)

    def snap_it(self, pos):
        newpos = round(pos[0] / GRID_SIZE_X) * GRID_SIZE_X, round(pos[1] / GRID_SIZE_Y) * GRID_SIZE_Y
        return newpos
