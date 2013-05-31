import pwn, os, struct, sys
from pwn import log, text

_raw_input = raw_input
try:
    import readline, atexit
    atexit.register(lambda: readline.set_startup_hook())
    def raw_input(prompt, suggestion = ''):
        readline.set_startup_hook(lambda: readline.insert_text(suggestion))
        s = _raw_input(prompt)
        readline.set_startup_hook()
        return s
except:
    def raw_input(prompt, suggestion = ''):
        return _raw_input(prompt)

if sys.stdin.isatty() and sys.stdout.isatty():
    import fcntl, sys, termios, tty
    def get_term_size():
        fd = os.open(os.ctermid(), os.O_RDONLY)
        height, width = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
        os.close(fd)
        return width, height

    def options(prompt, opts, default = None):
        try:
            if default is not None:
                default = int(default)
        except:
            pwn.die('default value must be a number in options')
        linefmt = '       %' + str(len(str(len(opts)))) + 'd) %s'
        choice = default
        pos = 0 if default is None else len(str(default))
        max_pos = pos
        offset = len(prompt) + 6

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                width, _ = get_term_size()
                s = '\x1b[G\x1b[K ' + text.bold('[?]') + ' %s' % prompt
                if choice:
                    s += ' %d' % choice
                sys.stdout.write(s)
                for i, opt in enumerate(opts):
                    s = linefmt % (i + 1, opt)
                    if i + 1 == choice:
                        s = text.cyanbg(s.ljust(width))
                    sys.stdout.write('\r\n\x1b[K' + s)
                sys.stdout.write('\x1b[%dF\x1b[%dC' % (len(opts), offset + pos))

                ch = pwn.u8(sys.stdin.read(1))
                if   ch == 3: # ^C
                    raise KeyboardInterrupt
                elif ch == 4: # ^D
                    raise EOFError
                elif ch == 127: # Backspace
                    if pos > 0:
                        s = str(choice)
                        s = s[:pos-1] + s[pos:]
                        if s:
                            choice = int(s)
                            pos -= 1
                            max_pos -= 1
                        else:
                            choice = None
                            pos = 0
                            max_pos = 0
                elif ch in range(48, 58): # 0 - 9
                    n = ch - 48
                    s = str(choice or '')
                    n = int(s[:pos] + str(n) + s[pos:])
                    if n >= 1 and n <= len(opts):
                        choice = n
                        pos += 1
                        max_pos += 1
                elif ch == 13: # Enter
                    break
                elif ch == 27:
                    ch = pwn.u8(sys.stdin.read(1))
                    if ch <> 91: continue
                    ch = pwn.u8(sys.stdin.read(1))
                    if   ch == 68: # Left
                        pos = max(pos - 1, 0)
                    elif ch == 67: # Right
                        pos = min(pos + 1, max_pos)
                    elif ch == 65: # Up
                        if choice is None:
                            choice = 1
                            pos = 1
                            max_pos = pos
                        if choice > 1:
                            choice -= 1
                            pos = len(str(choice))
                            max_pos = pos
                    elif ch == 66: # Down
                        if choice is None:
                            choice = len(opts)
                            pos = len(str(choice))
                            max_pos = pos
                        if choice < len(opts):
                            choice += 1
                            pos = len(str(choice))
                            max_pos = pos
                    elif ch == 51: # Delete
                        ch = pwn.u8(sys.stdin.read(1))
                        if ch <> 126: continue
                        if pos < max_pos:
                            s = str(choice)
                            s = s[:pos] + s[pos+1:]
                            if s:
                                choice = int(s)
                                max_pos -= 1
                            else:
                                choice = None
                                pos = 0
                                max_pos = 0
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            sys.stdout.write('\x1b[%dB\n' % len(opts))
        return choice

    def _restore_at_exit():
        import atexit
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        def restore():
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

            # This turns on the cursor
            sys.stdout.write('\x1b[?25h')
            sys.stdout.flush()
        atexit.register(restore)
    _restore_at_exit()

else:
    def get_term_size():
        return 80, 24

    def options(prompt, opts, default = None):
        try:
            if default is not None:
                default = int(default)
        except:
            pwn.die('default value must be a number in options')
        linefmt = '       %' + str(len(str(len(opts)))) + 'd) %s'
        while True:
            print ' [?] ' + prompt
            for i, opt in enumerate(opts):
                print linefmt % (i + 1, opt)
            s = '     Choice '
            if default:
                s += '[%s] ' % str(default)
            try:
                x = int(raw_input(s) or default)
            except (ValueError, TypeError):
                continue
            if x >= 1 and x <= len(opts):
                return x

def pause(n = None):
    """Waits for either user input or a specific number of seconds."""
    try:
        if n is None:
            log.info('Paused (press enter to continue)')
            raw_input('')
        else:
            log.waitfor('Continueing in')
            for i in range(n, 0, -1):
                log.status('%d... ' % i)
                pwn.sleep(1)
            log.succeeded('Now')
    except KeyboardInterrupt:
        log.warning('Interrupted')
        sys.exit(1)

def prompt(s, default = '', suggestion = ''):
    """Prompts the user for input"""
    s = ' ' + text.bold('[?]') + ' ' + s + ' '
    if default:
        s += '[%s] ' % default
    return raw_input(s, suggestion) or default

def yesno(s, default = None):
    """Prompt the user for an yes/no answer"""
    s = ' ' + text.bold('[?]') + ' ' + s + ' '
    while True:
        if   default == True:
            x = raw_input(s + '[Y/n] ') or 'y'
        elif default == False:
            x = raw_input(s + '[y/N] ') or 'n'
        else:
            x = raw_input(s + '[y/n] ')
        if not x: continue
        if x in 'yY': return True
        if x in 'nN': return False
