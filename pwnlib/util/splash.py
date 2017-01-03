"""Silly module mostly meant as an easter-egg."""
from __future__ import absolute_import

import threading
import time

from pwnlib import term
from pwnlib.term import text


_banner = r'''
  .:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:.
  )     _____                         _    _                            )
  (    |  _  |___ _ _ _ ___ ___ ___ _| |  | |_ _ _                      (
  )    |   __| . | | | | -_|  _| -_| . |  | . | | |                     )
  (    |__|  |___|_____|___|_| |___|___|  |___|_  |                     (
  )          _____                         __ |___|     __              )
  (         /\  __`\                      /\ \       __/\ \             (
  )         \ \ \/\ \__  __  __   ____    \ \ \     /\_\ \ \___         )
  (          \ \ ,__/\ \/\ \/\ \ /  _ `\   \ \ \    \/\ \ \  __`\       (
  )           \ \ \/\ \ \_/ \_/ \ \ \/\ \   \ \ \____\ \ \ \ \/\ \      )
  (            \ \_\ \ \___^___/'\ \_\ \_\   \ \_____\\ \_\ \____/      (
  )             \/_/  \/__//__/   \/_/\/_/    \/_____/ \/_/\/___/       )
  (                                                                     (
  .:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:.
'''

def splash():
    """Put this at the beginning of your exploit to create the illusion that
    your sploit is enterprisey and top notch quality"""

    def updater():

        colors = [
            text.blue   , text.bold_blue   ,
            text.magenta, text.bold_magenta,
            text.red    , text.bold_red    ,
            text.yellow , text.bold_yellow ,
            text.green  , text.bold_green  ,
            text.cyan   , text.bold_cyan   ,
        ]
        def getcolor(n):
            return colors[(n / 4) % len(colors)]

        lines = ['    ' + line + '\n' for line in _banner.strip('\n').split('\n')]

        hs = [term.output('', frozen = False) for _ in range(len(lines))]
        ndx = 0
        import sys as _sys
        while _sys:
            for i, (l, h) in enumerate(zip(lines, hs)):
                cur = ''
                buf = ''
                col = getcolor(ndx + i)
                for j in range(len(l)):
                    buf += l[j]
                    ncol = getcolor(ndx + i + j)
                    if col != ncol:
                        cur += buf if buf.isspace() else col(buf)
                        col = ncol
                        buf = ''
                cur += col(buf)
                h.update(cur)
            ndx += 1
            time.sleep(0.15)

    if term.term_mode:
        t = threading.Thread(target = updater)
        t.daemon = True
        t.start()
        time.sleep(0.2)
