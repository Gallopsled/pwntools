from __future__ import absolute_import
from __future__ import division

import os
import signal
import six
import string
import struct
import subprocess
import sys
import time
import types

from pwnlib import term
from pwnlib.log import getLogger
from pwnlib.term.readline import raw_input
from pwnlib.tubes.process import process

log = getLogger(__name__)

def testpwnproc(cmd):
    import fcntl
    import termios
    env = dict(os.environ)
    env.pop("PWNLIB_NOTERM", None)
    env["TERM"] = "xterm-256color"
    def handleusr1(sig, frame):
        s = p.stderr.read()
        log.error("child process failed:\n%s", s.decode())
    signal.signal(signal.SIGUSR1, handleusr1)
    cmd = """\
import os
import signal
import sys
_ehook = sys.excepthook
def ehook(*args):
    _ehook(*args)
    os.kill(os.getppid(), signal.SIGUSR1)
sys.excepthook = ehook
from pwn import *
""" + cmd
    if "coverage" in sys.modules:
        cmd = "import coverage; coverage.process_startup()\n" + cmd
        env.setdefault("COVERAGE_PROCESS_START", ".coveragerc")
    p = process([sys.executable, "-c", cmd], env=env, stderr=subprocess.PIPE)
    try:
        p.recvuntil(b"\33[6n")
    except EOFError:
        raise EOFError("process terminated with code: %r (%r)" % (p.poll(True), p.stderr.read()))
    # late initialization can lead to EINTR in many places
    fcntl.ioctl(p.stdout.fileno(), termios.TIOCSWINSZ, struct.pack("hh", 80, 80))
    p.stdout.write(b"\x1b[1;1R")
    time.sleep(0.5)
    return p

def yesno(prompt, default=None):
    r"""Presents the user with prompt (typically in the form of question)
    which the user must answer yes or no.

    Arguments:
      prompt (str): The prompt to show
      default: The default option;  `True` means "yes"

    Returns:
      `True` if the answer was "yes", `False` if "no"

    Examples:

    .. doctest::
       :skipif: branch_dev

        >>> yesno("A number:", 20)
        Traceback (most recent call last):
        ...
        ValueError: yesno(): default must be a boolean or None
        >>> saved_stdin = sys.stdin
        >>> try:
        ...     sys.stdin = io.TextIOWrapper(io.BytesIO(b"x\nyes\nno\n\n"))
        ...     yesno("is it good 1")
        ...     yesno("is it good 2", True)
        ...     yesno("is it good 3", False)
        ... finally:
        ...     sys.stdin = saved_stdin
         [?] is it good 1 [yes/no] Please answer yes or no
         [?] is it good 1 [yes/no] True
         [?] is it good 2 [Yes/no] False
         [?] is it good 3 [yes/No] False

    Tests:

    .. doctest::
       :skipif: branch_dev

        >>> p = testpwnproc("print(yesno('is it ok??'))")
        >>> b"is it ok" in p.recvuntil(b"??")
        True
        >>> p.sendline(b"x\nny")
        >>> b"True" in p.recvall()
        True
    """

    if default is not None and not isinstance(default, bool):
        raise ValueError('yesno(): default must be a boolean or None')

    if term.term_mode:
        term.output(' [?] %s [' % prompt)
        yesfocus, yes = term.text.bold('Yes'), 'yes'
        nofocus, no = term.text.bold('No'), 'no'
        hy = term.output(yesfocus if default is True else yes)
        term.output('/')
        hn = term.output(nofocus if default is False else no)
        term.output(']\n')
        cur = default
        while True:
            k = term.key.get()
            if   k in ('y', 'Y', '<left>') and cur is not True:
                cur = True
                hy.update(yesfocus)
                hn.update(no)
            elif k in ('n', 'N', '<right>') and cur is not False:
                cur = False
                hy.update(yes)
                hn.update(nofocus)
            elif k == '<enter>':
                if cur is not None:
                    return cur
    else:
        prompt = ' [?] %s [%s/%s] ' % (prompt,
                                       'Yes' if default is True else 'yes',
                                       'No' if default is False else 'no',
                                       )
        while True:
            opt = raw_input(prompt).strip().lower()
            if not opt and default is not None:
                return default
            elif opt in (b'y', b'yes'):
                return True
            elif opt in (b'n', b'no'):
                return False
            print('Please answer yes or no')

def options(prompt, opts, default = None):
    r"""Presents the user with a prompt (typically in the
    form of a question) and a number of options.

    Arguments:
      prompt (str): The prompt to show
      opts (list): The options to show to the user
      default: The default option to choose

    Returns:
      The users choice in the form of an integer.

    Examples:

    .. doctest::
       :skipif: branch_dev

        >>> options("Select a color", ("red", "green", "blue"), "green")
        Traceback (most recent call last):
        ...
        ValueError: options(): default must be a number or None

    Tests:

    .. doctest::
       :skipif: branch_dev

        >>> p = testpwnproc("print(options('select a color', ('red', 'green', 'blue')))")
        >>> p.sendline(b"\33[C\33[A\33[A\33[B\33[1;5A\33[1;5B 0310")
        >>> _ = p.recvall()
        >>> saved_stdin = sys.stdin
        >>> try:
        ...     sys.stdin = io.TextIOWrapper(io.BytesIO(b"\n4\n\n3\n"))
        ...     with context.local(log_level="INFO"):
        ...         options("select a color A", ("red", "green", "blue"), 0)
        ...         options("select a color B", ("red", "green", "blue"))
        ... finally:
        ...     sys.stdin = saved_stdin
         [?] select a color A
               1) red
               2) green
               3) blue
             Choice [1] 0
         [?] select a color B
               1) red
               2) green
               3) blue
             Choice  [?] select a color B
               1) red
               2) green
               3) blue
             Choice  [?] select a color B
               1) red
               2) green
               3) blue
             Choice 2
    """

    if default is not None and not isinstance(default, six.integer_types):
        raise ValueError('options(): default must be a number or None')

    if term.term_mode:
        numfmt = '%' + str(len(str(len(opts)))) + 'd) '
        print(' [?] ' + prompt)
        hs = []
        space = '       '
        arrow = term.text.bold_green('    => ')
        cur = default
        for i, opt in enumerate(opts):
            h = term.output(arrow if i == cur else space, frozen = False)
            num = numfmt % (i + 1)
            term.output(num)
            term.output(opt + '\n', indent = len(num) + len(space))
            hs.append(h)
        ds = ''
        while True:
            prev = cur
            was_digit = False
            k = term.key.get()
            if   k == '<up>':
                if cur is None:
                    cur = 0
                else:
                    cur = max(0, cur - 1)
            elif k == '<down>':
                if cur is None:
                    cur = 0
                else:
                    cur = min(len(opts) - 1, cur + 1)
            elif k == 'C-<up>':
                cur = 0
            elif k == 'C-<down>':
                cur = len(opts) - 1
            elif k in ('<enter>', '<right>'):
                if cur is not None:
                    return cur
            elif k in tuple(string.digits):
                was_digit = True
                d = str(k)
                n = int(ds + d)
                if 0 < n <= len(opts):
                    ds += d
                    cur = n - 1
                elif d != '0':
                    ds = d
                    n = int(ds)
                    cur = n - 1

            if prev != cur:
                if prev is not None:
                    hs[prev].update(space)
                if was_digit:
                    hs[cur].update(term.text.bold_green('%5s> ' % ds))
                else:
                    hs[cur].update(arrow)
    else:
        linefmt =       '       %' + str(len(str(len(opts)))) + 'd) %s'
        if default is not None:
            default += 1
        while True:
            print(' [?] ' + prompt)
            for i, opt in enumerate(opts):
                print(linefmt % (i + 1, opt))
            s = '     Choice '
            if default:
                s += '[%s] ' % str(default)
            try:
                x = int(raw_input(s) or default)
            except (ValueError, TypeError):
                continue
            if x >= 1 and x <= len(opts):
                return x - 1

def pause(n=None):
    r"""Waits for either user input or a specific number of seconds.

    Examples:

    .. doctest::
       :skipif: branch_dev

        >>> with context.local(log_level="INFO"):
        ...     pause(1)
        [x] Waiting
        [x] Waiting: 1...
        [+] Waiting: Done
        >>> pause("whatever")
        Traceback (most recent call last):
        ...
        ValueError: pause(): n must be a number or None

    Tests:

    .. doctest::
       :skipif: branch_dev

        >>> saved_stdin = sys.stdin
        >>> try:
        ...     sys.stdin = io.TextIOWrapper(io.BytesIO(b"\n"))
        ...     with context.local(log_level="INFO"):
        ...         pause()
        ... finally:
        ...     sys.stdin = saved_stdin
        [*] Paused (press enter to continue)
        >>> p = testpwnproc("pause()")
        >>> b"Paused" in p.recvuntil(b"press any")
        True
        >>> p.send(b"x")
        >>> _ = p.recvall()
    """

    if n is None:
        if term.term_mode:
            log.info('Paused (press any to continue)')
            term.getkey()
        else:
            log.info('Paused (press enter to continue)')
            raw_input('')
    elif isinstance(n, six.integer_types):
        with log.waitfor("Waiting") as l:
            for i in range(n, 0, -1):
                l.status('%d... ' % i)
                time.sleep(1)
            l.success()
    else:
        raise ValueError('pause(): n must be a number or None')

def more(text):
    r"""more(text)

    Shows text like the command line tool ``more``.

    It not in term_mode, just prints the data to the screen.

    Arguments:
      text(str):  The text to show.

    Returns:
      :const:`None`

    Tests:

    .. doctest::
       :skipif: branch_dev
       
        >>> more("text")
        text
        >>> p = testpwnproc("more('text\\n' * (term.height + 2))")
        >>> p.send(b"x")
        >>> data = p.recvall()
        >>> b"text" in data or data
        True
    """
    if term.term_mode:
        lines = text.split('\n')
        h = term.output(term.text.reverse('(more)'), float = True, frozen = False)
        step = term.height - 1
        for i in range(0, len(lines), step):
            for l in lines[i:i + step]:
                print(l)
            if i + step < len(lines):
                term.key.get()
        h.delete()
    else:
        print(text)
