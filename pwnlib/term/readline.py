# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import six
import sys

from pwnlib.term import keyconsts as kc
from pwnlib.term import keymap as km
from pwnlib.term import term
from pwnlib.term import text

cursor = text.reverse

buffer_left, buffer_right = '', ''
saved_buffer = None
history = []
history_idx = None
prompt_handle = None
buffer_handle = None
suggest_handle = None
search_idx = None
search_results = []
startup_hook = None
shutdown_hook = None

delims = ' /;:.\\'

show_completion = True
show_suggestions = False

complete_hook = None
suggest_hook = None

tabs = 0

def force_to_bytes(data):
    if isinstance(data, bytes):
        return data
    try:
        return data.encode('utf-8')
    except Exception:
        return data.encode('latin-1')

def set_completer(completer):
    global complete_hook, suggest_hook
    if completer is None:
        complete_hook = None
        suggest_hook = None
    else:
        complete_hook = completer.complete
        suggest_hook = completer.suggest

def fmt_suggestions(suggestions):
    if suggestions:
        s = ''
        l = max(map(len, suggestions))
        columns = term.width // (l + 1)
        column_width = term.width // columns
        fmt = '%%-%ds' % column_width
        for j in range(0, len(suggestions), columns):
            for k in range(columns):
                l = j + k
                if l < len(suggestions):
                    s += fmt % suggestions[l]
            s += '\n'
    else:
        s = '(no completions)\n'
    return s

def auto_complete(*_):
    global show_suggestions, tabs
    if search_idx is not None:
        commit_search()
        tabs = 0
    elif tabs == 1:
        if complete_hook:
            ret = complete_hook(buffer_left, buffer_right)
            if ret:
                tabs = 0
                insert_text(ret)
    else:
        show_suggestions = not show_suggestions
        redisplay()

def handle_keypress(trace):
    global tabs
    k = trace[-1]
    if k == '<tab>':
        tabs += 1
    else:
        tabs = 0

def clear():
    global buffer_left, buffer_right, history_idx, search_idx
    buffer_left, buffer_right = '', ''
    history_idx = None
    search_idx = None
    redisplay()

def redisplay():
    global suggest_handle
    if buffer_handle:
        if show_suggestions and suggest_hook:
            suggestions = suggest_hook(buffer_left, buffer_right)
            if suggest_handle is None:
                h = prompt_handle or buffer_handle
                suggest_handle = term.output(before = h)
            s = fmt_suggestions(suggestions)
            suggest_handle.update(s)
        elif suggest_handle:
            suggest_handle.update('')
        if search_idx is None:
            s = None
            if buffer_right:
                s = buffer_left + cursor(buffer_right[0]) + buffer_right[1:]
            elif show_completion and complete_hook:
                ret = complete_hook(buffer_left, buffer_right)
                if ret:
                    s = buffer_left + \
                      text.underline(cursor(ret[0])) + \
                      text.underline(ret[1:])
            s = s or buffer_left + cursor(' ')
            buffer_handle.update(s)
        else:
            if search_results != []:
                idx, i, j = search_results[search_idx]
                buf = history[idx]
                a, b, c = buf[:i], buf[i:j], buf[j:]
                s = a + text.bold_green(b) + c
            else:
                s = text.white_on_red(buffer_left)
            buffer_handle.update('(search) ' + s)

def self_insert(trace):
    if len(trace) != 1:
        return
    k = trace[0]
    if k.type == kc.TYPE_UNICODE and k.mods == kc.MOD_NONE:
        insert_text(k.code)

def set_buffer(left, right):
    global buffer_left, buffer_right
    buffer_left = left
    buffer_right = right
    redisplay()

def cancel_search(*_):
    global search_idx
    if search_idx is not None:
        search_idx = None
        redisplay()

def commit_search():
    global search_idx
    if search_idx is not None and search_results:
        set_buffer(history[search_results[search_idx][0]], '')
        search_idx = None
        redisplay()

def update_search_results():
    global search_results, search_idx, show_suggestions
    if search_idx is None:
        return
    show_suggestions = False
    if search_results:
        hidx = search_results[search_idx][0]
    else:
        hidx = None
    search_results = []
    search_idx = 0
    if not buffer_left:
        return
    for idx, h in enumerate(history):
        for i in range(0, len(h) - len(buffer_left) + 1):
            if h[i:i + len(buffer_left)] == buffer_left:
                if hidx is not None and idx == hidx:
                    search_idx = len(search_results)
                search_results.append((idx, i, i + len(buffer_left)))
                break

def search_history(*_):
    global buffer_left, buffer_right, history_idx, search_idx
    if search_idx is None:
        buffer_left, buffer_right = buffer_left + buffer_right, ''
        history_idx = None
        search_idx = 0
        update_search_results()
    elif search_results:
        search_idx = (search_idx + 1) % len(search_results)
    redisplay()

def history_prev(*_):
    global history_idx, saved_buffer
    if history == []:
        return
    cancel_search()
    if history_idx is None:
        saved_buffer = (buffer_left, buffer_right)
        history_idx = -1
    if history_idx < len(history) - 1:
        history_idx += 1
        set_buffer(history[history_idx], '')

def history_next(*_):
    global history_idx, saved_buffer
    if history_idx is None:
        return
    cancel_search()
    if history_idx == 0:
        set_buffer(*saved_buffer)
        history_idx = None
        saved_buffer = None
    else:
        history_idx -= 1
        set_buffer(history[history_idx], '')

def backward_char(*_):
    global buffer_left, buffer_right
    commit_search()
    if buffer_left:
        buffer_right = buffer_left[-1] + buffer_right
        buffer_left = buffer_left[:-1]
    redisplay()

def forward_char(*_):
    global buffer_left, buffer_right
    commit_search()
    if buffer_right:
        buffer_left += buffer_right[0]
        buffer_right = buffer_right[1:]
    redisplay()

def insert_text(s):
    global history_idx, saved_buffer, buffer_left
    if history_idx is not None:
        history_idx = None
        saved_buffer = None
    buffer_left += s
    update_search_results()
    redisplay()

def submit(*_):
    if search_idx is not None:
        commit_search()
    else:
        keymap.stop()

def control_c(*_):
    global history_idx, saved_buffer
    if search_idx is not None:
        cancel_search()
    elif history_idx is not None:
        set_buffer(*saved_buffer)
        history_idx = None
        saved_buffer = None
    elif buffer_left or buffer_right:
        clear()
    else:
        raise KeyboardInterrupt

def control_d(*_):
    if buffer_left or buffer_right:
        return
    global eof
    eof = True
    keymap.stop()

def kill_to_end(*_):
    global buffer_right
    commit_search()
    buffer_right = []
    redisplay()

def delete_char_forward(*_):
    global buffer_right
    commit_search()
    if buffer_right:
        buffer_right = buffer_right[1:]
        redisplay()

def delete_char_backward(*_):
    global buffer_left
    if buffer_left:
        buffer_left = buffer_left[:-1]
        update_search_results()
        redisplay()

def kill_word_backward(*_):
    global buffer_left
    commit_search()
    flag = False
    while buffer_left:
        c = buffer_left[-1]
        if c[0] in delims:
            if flag:
                break
        else:
            flag = True
        buffer_left = buffer_left[:-1]
    redisplay()

def backward_word(*_):
    global buffer_left, buffer_right
    commit_search()
    flag = False
    while buffer_left:
        c = buffer_left[-1]
        if c[0] in delims:
            if flag:
                break
        else:
            flag = True
        buffer_right = buffer_left[-1] + buffer_right
        buffer_left = buffer_left[:-1]
    redisplay()

def forward_word(*_):
    global buffer_left, buffer_right
    commit_search()
    flag = False
    while buffer_right:
        c = buffer_right[0]
        if c[0] in delims:
            if flag:
                break
        else:
            flag = True
        buffer_left += buffer_right[0]
        buffer_right = buffer_right[1:]
    redisplay()

def go_beginning(*_):
    commit_search()
    set_buffer('', buffer_left + buffer_right)

def go_end(*_):
    commit_search()
    set_buffer(buffer_left + buffer_right, '')

keymap = km.Keymap({
    '<nomatch>'   : self_insert,
    '<up>'        : history_prev,
    '<down>'      : history_next,
    '<left>'      : backward_char,
    '<right>'     : forward_char,
    '<del>'       : delete_char_backward,
    '<delete>'    : delete_char_forward,
    '<enter>'     : submit,
    'C-j'         : submit,
    'C-<left>'    : backward_word,
    'C-<right>'   : forward_word,
    'M-<left>'    : backward_word,
    'M-<right>'   : forward_word,
    'C-c'         : control_c,
    'C-d'         : control_d,
    'C-k'         : kill_to_end,
    'C-w'         : kill_word_backward,
    '<backspace>' : kill_word_backward,
    'M-<del>'     : kill_word_backward,
    'C-r'         : search_history,
    '<escape>'    : cancel_search,
    'C-a'         : go_beginning,
    'C-e'         : go_end,
    '<tab>'       : auto_complete,
    '<any>'       : handle_keypress,
    })

def readline(_size=-1, prompt='', float=True, priority=10):
    # The argument  _size is unused, but is there for compatibility
    # with the existing readline

    global buffer_handle, prompt_handle, suggest_handle, eof, \
        show_suggestions

    # XXX circular imports
    from pwnlib.term import term_mode
    if not term_mode:
        six.print_(prompt, end='', flush=True)
        return getattr(sys.stdin, 'buffer', sys.stdin).readline(_size).rstrip(b'\n')
    show_suggestions = False
    eof = False
    if prompt:
        prompt_handle = term.output(prompt, float = float, priority = priority)
    else:
        prompt_handle = None
    buffer_handle = term.output(float = float, priority = priority)
    suggest_handle = None
    clear()
    if startup_hook:
        startup_hook()
    try:
        while True:
            try:
                try:
                    keymap.handle_input()
                except EOFError:
                    if len(buffer_left + buffer_right) == 0:
                        return b''
                if eof:
                    return b''
                else:
                    buffer = (buffer_left + buffer_right)
                    if buffer:
                        history.insert(0, buffer)
                    return force_to_bytes(buffer) + b'\n'
            except KeyboardInterrupt:
                control_c()
    finally:
        line = buffer_left + buffer_right + '\n'
        buffer_handle.update(line)
        buffer_handle.freeze()
        buffer_handle = None
        if prompt_handle:
            prompt_handle.freeze()
            prompt_handle = None
        if suggest_handle:
            suggest_handle.freeze()
            suggest_handle = None
        if shutdown_hook:
            shutdown_hook()

def raw_input(prompt='', float=True):
    r"""raw_input(prompt='', float=True)

    Replacement for the built-in ``raw_input`` using ``pwnlib`` readline
    implementation.

    Arguments:
        prompt(str): The prompt to show to the user.
        float(bool): If set to `True`, prompt and input will float to the
                     bottom of the screen when `term.term_mode` is enabled.
    """
    return readline(-1, prompt, float)

def str_input(prompt='', float=True):
    r"""str_input(prompt='', float=True)

    Replacement for the built-in ``input`` in python3 using ``pwnlib`` readline
    implementation.

    Arguments:
        prompt(str): The prompt to show to the user.
        float(bool): If set to `True`, prompt and input will float to the
                     bottom of the screen when `term.term_mode` is enabled.
    """
    return readline(-1, prompt, float).decode()

def eval_input(prompt='', float=True):
    """eval_input(prompt='', float=True)

    Replacement for the built-in python 2 - style ``input`` using
    ``pwnlib`` readline implementation, and `pwnlib.util.safeeval.expr`
    instead of ``eval`` (!).

    Arguments:
        prompt(str): The prompt to show to the user.
        float(bool): If set to ``True``, prompt and input will float to the
                     bottom of the screen when `term.term_mode` is enabled.

    Example:

        >>> try:
        ...     saved = sys.stdin, pwnlib.term.term_mode
        ...     pwnlib.term.term_mode = False
        ...     sys.stdin = io.TextIOWrapper(io.BytesIO(b"{'a': 20}"))
        ...     eval_input("Favorite object? ")['a']
        ... finally:
        ...     sys.stdin, pwnlib.term.term_mode = saved
        Favorite object? 20
    """
    from pwnlib.util import safeeval
    return safeeval.const(readline(-1, prompt, float))

def init():
    global safeeval
    # defer imports until initialization
    import sys
    from six.moves import builtins
    from pwnlib.util import safeeval

    class Wrapper:
        def __init__(self, fd):
            self._fd = fd
        def readline(self, size = None):
            return readline(size)
        def __getattr__(self, k):
            return self._fd.__getattribute__(k)
    sys.stdin = Wrapper(sys.stdin)

    if six.PY2:
        builtins.raw_input = raw_input
        builtins.input = eval_input
    else:
        builtins.input = str_input
