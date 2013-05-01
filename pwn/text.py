import sys

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
# depends on intensity level
DARKGRAY = BLACK
GRAY = WHITE

if sys.stderr.isatty():
    def _reset(s):
        rst = '\x1b[0m'
        if s.endswith(rst):
            return s
        return s + rst

    def _code(c, s):
        return _reset('\x1b[%dm%s' % (c, s))

    def color(c, s):
        return _code(c + 30, s)

    def background(c, s):
        return _code(c + 40, s)

    def bold(s):
        return _code(1, s)

    def italic(s):
        return _code(3, s)

    def underline(s):
        return _code(4, s)

else:
    def color(c, s):
        return s

    def background(c, s):
        return s

    def bold(s):
        return s

    def italic(s):
        return s

    def underline(s):
        return s

# Text color aliases
def red(s):
    return color(RED, s)

def green(s):
    return color(GREEN, s)

def yellow(s):
    return color(YELLOW, s)

def blue(s):
    return color(BLUE, s)

def magenta(s):
    return color(MAGENTA, s)

def cyan(s):
    return color(CYAN, s)

def white(s):
    return color(WHITE, s)

# Bold colored text aliases
def boldred(s):
    return bold(color(RED, s))

def boldgreen(s):
    return bold(color(GREEN, s))

def boldyellow(s):
    return bold(color(YELLOW, s))

def boldblue(s):
    return bold(color(BLUE, s))

def boldmagenta(s):
    return bold(color(MAGENTA, s))

def boldcyan(s):
    return bold(color(CYAN, s))

def boldwhite(s):
    return bold(color(WHITE, s))

# Background color aliases
def redbg(s):
    return background(RED, s)

def greenbg(s):
    return background(GREEN, s)

def yellowbg(s):
    return background(YELLOW, s)

def bluebg(s):
    return background(BLUE, s)

def magentabg(s):
    return background(MAGENTA, s)

def cyanbg(s):
    return background(CYAN, s)

def whitebg(s):
    return background(WHITE, s)

