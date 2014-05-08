import readline
from ..lib import log

if readline.available:
    class Completer:
        def complete (self, _left, _right):
            log.stub()
        def suggest (self, _left, _right):
            log.stub()
        def __enter__ (self):
            self._saved_complete_hook = readline.complete_hook
            self._saved_suggest_hook = readline.suggest_hook
            self._saved_show_suggestions_hook = readline.show_suggestions_hook
            readline.set_completer(self)
            if hasattr(self, 'show_suggestions'):
                readline.show_suggestions_hook = self.show_suggestions
        def __exit__ (self, *args):
            readline.complete_hook = self._saved_complete_hook
            readline.suggest_hook = self._saved_suggest_hook
            readline.show_suggestions = self._saved_show_suggestions_hook

    class WordCompleter(Completer):
        def __init__ (self, delims = None):
            self.delims = delims or ' \t\n`!@#$^&*()=+[{]}\\|;:\'",<>?'
            self._cur_word = None
            self._completions = []

        def _get_word (self, left):
            i = len(left) - 1
            while i >= 0:
                # XXX: fix when we port to unicode
                if left[i][0] in self.delims:
                    break
                i -= 1
            i += 1
            return left[i:]

        def _update_result (self, w):
            if w == self._cur_word:
                return
            self._cur_word = w
            self._completions = self.complete_word(''.join(w)) # XXX: unicode!

        def complete (self, buffer_left, buffer_right):
            w = self._get_word(buffer_left)
            self._update_result(w)
            if len(self._completions) == 1:
                c = self._completions[0]
                if len(c) > len(w):
                    return (buffer_left + list(self._completions[0][len(w):]),
                            buffer_right)
                else:
                    return (buffer_left, buffer_right)

        def suggest (self, buffer_left, _buffer_right):
            w = self._get_word(buffer_left)
            self._update_result(w)
            return self._completions

        def complete_word (self, word):
            log.stub()

    class LongestPrefixCompleter(WordCompleter):
        def __init__ (self, words = [], delims = None):
            WordCompleter.__init__(self, delims)
            self.words = words

        def complete_word (self, word):
            if not word:
                return []
            cs = [w for w in self.words if w.startswith(word)]
            if cs == []:
                return cs
            lpf = word
            shortest = min(map(len, cs))
            while len(lpf) < shortest:
                i = len(lpf)
                ch = cs[0][i]
                if any(c[i] <> ch for c in cs[1:]):
                    break
                lpf += ch
            if len(lpf) > len(word):
                return [lpf]
            else:
                return cs
