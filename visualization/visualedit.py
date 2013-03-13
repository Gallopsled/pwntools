import pygame, sys
from PIL import Image
pygame.init()

def displayImage(screen, px, topleft, prior):
    # ensure that the rect always has positive width, height
    x, y = topleft
    width =  pygame.mouse.get_pos()[0] - topleft[0]
    height = pygame.mouse.get_pos()[1] - topleft[1]
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

def setup(path):
    px = pygame.image.load(path)
    screen = pygame.display.set_mode( px.get_rect()[2:] )
    screen.blit(px, px.get_rect())
    pygame.display.flip()
    return screen, px

def mainLoop(screen, px):
    topleft = bottomright = prior = None
    n=0
    while n!=1:
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONUP:
                if not topleft:
                    topleft = event.pos
                else:
                    bottomright = event.pos
                    n=1
        if topleft:
            prior = displayImage(screen, px, topleft, prior)
    return ( topleft + bottomright )

if __name__ == "__main__":
    input_loc = 'output.png'
    output_loc = 'outtest.png'
    screen, px = setup(input_loc)
    while True:
        try:
            left, upper, right, lower = mainLoop(screen, px)
            print "Found something in boundary box: (%s, %s, %s, %s)" % (left, upper, right, lower)
        except KeyboardInterrupt:
            print "got a keyboard interrupt, putting myself to sleep"
            break

    # left the following code in case we want to save it out somehow... nice to have
    # ensure output rectangle always has positive width and height
    # if right < left:
    #     left, right = right, left
    # if lower < upper:
    #     lower, upper = upper, lower
    # im = Image.open(input_loc)
    # im = im.crop(( left, upper, right, lower))
    # pygame.display.quit()
    # im.save(output_loc)
