import termios, tty, sys, string, time

def get_term_size():
    fd = os.open(os.ctermid(), os.O_RDONLY)
    height, width = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
    os.close(fd)
    return width, height

def get_cursor_pos():
    sys.stdout.write("\033[6n")
    s = ''
    while True:
        c = sys.stdin.read(1)
        if c == 'R':
            break
        s += c
    col, row = map(int, s[2:].split(';'))
    return col, row

fd = sys.stdin.fileno()
old_settings = termios.tcgetattr(fd)
tty.setraw(sys.stdin.fileno())

while True:
    # print 'At (%d, %d)' % get_cursor_pos()
    c = sys.stdin.read(1)
    if c == 'q':
        break
    if c == '\r':
        print
    if c == 'w':
        s = '\x01\x1b[s\x1b[50Ayolo\x1b[u\x02'
        sys.stdout.write(s)
    if c == 'e':
        sys.stdout.write('\x1b[s')
        for i in range(100):
            sys.stdout.write('\x1b[0;15f%s' % '/-\\|'[i % 4])
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\x1b[u')
    if c == 'E':
        sys.stdout.write('\x1b[s')
        for i in range(100):
            sys.stdout.write('\x1b[0;15H%s' % '.oO*'[i % 4])
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\x1b[u')
    if c == 'r':
        sys.stdout.write('\x1b[S')
    if c == 't':
        sys.stdout.write('\x1b[T')
    if c == 'y':
        sys.stdout.write('\x1b[syolo\r\n\x1b[ufoo')
    if c == 'u':
        x = ord('a')
        for i in range(10):
            sys.stdout.write('\x1b[A' + chr(x))
            sys.stdout.flush()
            time.sleep(0.3)
            x += 1
            sys.stdout.write('\x1b[B' + chr(x))
            sys.stdout.flush()
            time.sleep(0.3)
            x += 1
    if c in string.printable:
        sys.stdout.write(c)
    else:
        sys.stdout.write('\\x%02x' % ord(c))

termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
