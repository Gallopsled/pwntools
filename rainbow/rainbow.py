import sys
from datetime import datetime
COLORS = [1,2,3,4,5]

class rainbow:
    odd = speed = colidx = lasttime = -1

    def __init__(self, fps=10):
        self.speed = 1000000 / fps

    def pulsebar(self, text):
        if self.colidx < 0:
            self.colidx = 0
        now = datetime.now().strftime("%S%f")
        time = int(now[:2]) * 1000000 + int(now[2:])
        if abs(self.lasttime - time) >= self.speed:
            self.lasttime = time
            self.colidx = len(COLORS) - 1 if self.colidx == 0 else self.colidx - 1
        sys.stdout.write("\033[0;3%dm%s\033[0m" % (COLORS[self.colidx], text))
        #sys.stdout.flush()

    def scrollbar(self, text, colorlen=8):
        pos = i = 0
        textlen = len(text)
        if self.colidx < 0:
            self.colidx = 0
        if colorlen < 1:
            colorlen = 1
        if self.odd < 0:
            self.odd = colorlen - 1;

        now = datetime.now().strftime("%S%f")
        time = int(now[:2]) * 1000000 + int(now[2:])
        if abs(self.lasttime - time) >= self.speed:
            self.odd = (self.odd + 1) % colorlen
            self.lasttime = time
            if self.odd == 0:
                self.colidx = len(COLORS) - 1 if self.colidx == 0 else self.colidx - 1

        while pos < self.odd and pos < textlen:
            sys.stdout.write("\033[0;3%dm%c\033[0m" % (COLORS[self.colidx % len(COLORS)], text[pos]))
            pos += 1
        while pos < textlen:
            sys.stdout.write("\033[0;3%dm%c\033[0m" % (COLORS[(self.colidx + 1 + i / colorlen) % len(COLORS)], text[pos]))
            pos += 1
            i += 1
        sys.stdout.write("\033[0m");
        #sys.stdout.flush()

