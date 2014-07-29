"""Silly module mostly meant as an easter-egg."""

from .. import term, log
from ..term import text
import sys, time, threading

_banner = r'''
  .:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:.
  )     _____                         _    _                            )
  (    |  _  |___ _ _ _ ___ ___ ___ _| |  | |_ _ _                      (
  )    |   __| . | | | | -_|  _| -_| . |  | . | | |                     )
  (    |__|  |___|_____|___|_| |___|___|  |___|_  |                     (
  )          _____                         __ |___|     __              )
  (         /\  _ `\                      /\ \       __/\ \             (
  )         \ \ \Z\ \__  __  __   ____    \ \ \     /\_\ \ \___         )
  (          \ \ ,__/\ \/\ \/\ \ /  _ `\   \ \ \    \/\ \ \  _ `\       (
  )           \ \ \/\ \ \_/ \_/ \ \ \/\ \   \ \ \____\ \ \ \ \Z\ \      )
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
            text.blue,   text.magenta, text.red,
            text.yellow, text.green,   text.cyan,
        ]

        lines = _banner.strip('\n').split('\n')

        hs = [log.indented('', frozen = False) for _ in range(len(lines))]
        ndx = 0
        import sys as _sys
        while _sys:
            for i, (l, h) in enumerate(zip(lines, hs)):
                l = ''.join(colors[((ndx + i + j) / 3) % len(colors)](l[j]) \
                            for j in range(len(l))
                            )
                h.update(l)
            ndx += 1
            time.sleep(0.15)

    if term.term_mode:
        t = threading.Thread(target = updater)
        t.daemon = True
        t.start()
        time.sleep(0.2)
