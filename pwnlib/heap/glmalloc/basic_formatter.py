import shutil


def get_terminal_width():
    try:
        return shutil.get_terminal_size().columns
    except AttributeError:
        import os
        _, columns = os.popen('stty size', 'r').read().split()
        return columns


class BasicFormatter(object):
    _MAXIMUM_WIDTH = 80
    _MINIMUM_WIDTH = 40

    def __init__(self):
        term_width = get_terminal_width()

        if term_width > self._MAXIMUM_WIDTH:
            self.width = self._MAXIMUM_WIDTH
        elif term_width < self._MINIMUM_WIDTH:
            self.width = self._MINIMUM_WIDTH
        else:
            self.width = term_width

        self.title_surrounded_symbol = "="

    def super_header(self, title):
        msg = "{}\n".format(self.header(title, separator="+"))
        msg += "+" * self.width
        return msg

    def header(self, title, separator="="):
        side_len = self._calc_side_len(title)
        side = separator * side_len
        return "{} {} {}".format(side, title, side)

    def _calc_side_len(self, title):
        return int((self.width - len(title) - 2) / 2)

    def footer(self):
        return "=" * self.width

    def super_footer(self):
        return "+" * self.width
