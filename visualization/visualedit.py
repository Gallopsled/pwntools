import pygame, sys
from PIL import Image
pygame.init()

GRID_SIZE_X = 32 # bytes == pixels?
GRID_SIZE_Y = 32
BG_COLOR = (0,0,0)


def snap_it(pos):
    newpos = round(pos[0] / GRID_SIZE_X) * GRID_SIZE_X, round(pos[1] / GRID_SIZE_Y) * GRID_SIZE_Y
    return newpos

def displayImage(screen, px, topleft, prior):
    # ensure that the rect always has positive width, height
    x, y = topleft
    mouse_pos = pygame.mouse.get_pos()
    width, height = snap_it((mouse_pos[0] - topleft[0], mouse_pos[1] - topleft[1]))
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
    screen.blit(px, px.get_rect())
    im = pygame.Surface((width, height))
    im.fill((128, 128, 128))
    pygame.draw.rect(im, (32, 32, 32), im.get_rect(), 1)
    im.set_alpha(128)
    screen.blit(im, (x, y))
    pygame.display.flip()

    # return current box extents
    return (x, y, width, height)

def move(pos,scale,px,screen):
    x, y = pos
    #print pos,x
    rect = px.get_rect()
    screen.fill(BG_COLOR)
    print rect.width/scale
    print rect.height/scale
    print px
    px = pygame.transform.scale(px, [rect.width/scale, rect.height/scale])
    screen.blit(px, (rect[0]-x, rect[1]-y))
    pygame.display.flip()
    #px.rect.topleft = pr.rect.topleft[0] - x,

def setup(path):
    px = pygame.image.load(path)
    screen = pygame.display.set_mode( px.get_rect()[2:] )
    screen.blit(px, px.get_rect())
    pygame.display.flip()
    return screen, px

def mainLoop(screen, px):
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
                    SNAP_TO_GRID_TOPLEFT = snap_it(event.pos)
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
            SELECTION = displayImage(screen, px, SNAP_TO_GRID_TOPLEFT, SELECTION)
        if SNAP_TO_GRID_STOPIT:
            SNAP_TO_GRID_TOPLEFT = SNAP_TO_GRID_BOTTOMRIGHT = None
    return

if __name__ == "__main__":
    if len(sys.argv) <> 2:
        print "usage: <program> <intput_filename>"
        exit(0)
    else:
        input_loc = sys.argv[1]
    # input_loc = 'output.png'
        output_loc = 'outtest.png'
        screen, px = setup(input_loc)
        try:
            mainLoop(screen, px)
        except KeyboardInterrupt:
            print "got a keyboard interrupt... dying"
            exit(0)


    # left the following code in case we want to save it out somehow... nice to have
    # ensure output rectangle always has positive width and height

    # im = Image.open(input_loc)
    # im = im.crop(( left, upper, right, lower))
    # pygame.display.quit()
    # im.save(output_loc)
