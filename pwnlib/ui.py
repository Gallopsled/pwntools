from . import log, term
import time, types

def options(prompt, opts, default = None):
    """Presents the user with a prompt (typically in the
    form of a question) and a number of options.

    Args:
      prompt (str): The prompt to show
      opts (list): The options to show to the user
      default: The default option to choose

    Returns:
      The users choice in the form of an integer.
"""

    if not isinstance(default, (int, long, types.NoneType)):
        raise ValueError('options(): default must be a number or None')

    # XXX: Make this work nicer when in term mode

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

    if n == None:
        if term.term_mode:
            log.info('Paused (press any to continue)')
            term.getkey()
        else:
            log.info('Paused (press enter to continue)')
            raw_input('')
    elif isinstance(n, (int, long)):
        h = log.waitfor("Waiting")
        for i in range(n, 0, -1):
            log.status('%d... ' % i)
            time.sleep(1)
        log.done_success('Done', h)
    else:
        raise ValueError('options(): n must be a number or None')
