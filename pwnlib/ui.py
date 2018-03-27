from __future__ import absolute_import
from __future__ import division

import six
import time
import types

from pwnlib import term
from pwnlib.log import getLogger

log = getLogger(__name__)

def yesno(prompt, default = None):
    """Presents the user with prompt (typically in the form of question) which
    the user must answer yes or no.

    Arguments:
      prompt (str): The prompt to show
      default: The default option;  `True` means "yes"

    Returns:
      `True` if the answer was "yes", `False` if "no"
"""

    if not isinstance(default, (bool, types.NoneType)):
        raise ValueError('yesno(): default must be a boolean or None')

    if term.term_mode:
        term.output(' [?] %s [' % prompt)
        yesfocus, yes = term.text.bold('Yes'), 'yes'
        nofocus, no = term.text.bold('No'), 'no'
        hy = term.output(yesfocus if default == True else yes)
        term.output('/')
        hn = term.output(nofocus if default == False else no)
        term.output(']\n')
        cur = default
        while True:
            k = term.key.get()
            if   k in ('y', 'Y', '<left>') and cur != True:
                cur = True
                hy.update(yesfocus)
                hn.update(no)
            elif k in ('n', 'N', '<right>') and cur != False:
                cur = False
                hy.update(yes)
                hn.update(nofocus)
            elif k == '<enter>':
                if cur is not None:
                    return cur
    else:
        prompt = ' [?] %s [%s/%s] ' % (prompt,
                                       'Yes' if default == True else 'yes',
                                       'No' if default == False else 'no',
                                       )
        while True:
            opt = raw_input(prompt).lower()
            if opt == '' and default != None:
                return default
            elif opt in ('y','yes'):
                return True
            elif opt in ('n', 'no'):
                return False
            print('Please answer yes or no')

def options(prompt, opts, default = None):
    """Presents the user with a prompt (typically in the
    form of a question) and a number of options.

    Arguments:
      prompt (str): The prompt to show
      opts (list): The options to show to the user
      default: The default option to choose

    Returns:
      The users choice in the form of an integer.
"""

    if not isinstance(default, six.integer_types+(types.NoneType,)):
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
        prev = 0
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
            elif k in tuple('1234567890'):
                was_digit = True
                d = str(k)
                n = int(ds + d)
                if n > 0 and n <= len(opts):
                    ds += d
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
                return x

def pause(n = None):
    """Waits for either user input or a specific number of seconds."""

    if n == None:
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
    """more(text)

    Shows text like the command line tool ``more``.

    It not in term_mode, just prints the data to the screen.

    Arguments:
      text(str):  The text to show.

    Returns:
      :const:`None`
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
