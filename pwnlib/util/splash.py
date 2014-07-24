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
            text.yellow, text.green,   text.cyan
        ]

        h = log.indented('\n', frozen = False)
        lines = _banner.lstrip('\n')
        ndx = 0
        while sys:
            h.update(colors[ndx](lines))
            ndx = (ndx + 1) % len(colors)
            time.sleep(0.15)

    if term.term_mode:
        t = threading.Thread(target = updater)
        t.daemon = True
        t.start()
        time.sleep(0.2)
