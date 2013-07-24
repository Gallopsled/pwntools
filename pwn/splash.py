from pwn import sleep, log
from pwn.text import color

_banner = '''  .:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:.
  )     _____                         _    _                            )
  (    |  _  |___ _ _ _ ___ ___ ___ _| |  | |_ _ _                      (
  )    |   __| . | | | | -_|  _| -_| . |  | . | | |                     )
  (    |__|  |___|_____|___|_| |___|___|  |___|_  |                     (
  )          _____                         __ |___|     __              )
  (         /\\  _ `\\                      /\\ \\       __/\\ \\             (
  )         \\ \\ \\Z\\ \\__  __  __   ____    \\ \\ \\     /\\_\\ \\ \\___         )
  (          \\ \\ ,__/\\ \\/\\ \\/\\ \\ /  _ `\\   \\ \\ \\    \\/\\ \\ \\  _ `\\       (
  )           \\ \\ \\/\\ \\ \\_/ \\_/ \\ \\ \\/\\ \\   \\ \\ \\____\\ \\ \\ \\ \\Z\\ \\      )
  (            \\ \\_\\ \\ \\___^___/'\\ \\_\\ \\_\\   \\ \\_____\\\\ \\_\\ \\____/      (
  )             \\/_/  \\/__//__/   \\/_/\\/_/    \\/_____/ \\/_/\\/___/       )
  (                                                                     (
  .:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:.'''

_lines = _banner.split('\n')

def splash():
    """Put this at the beginning of your exploit to create the illusion that your sploit is enterprisey and top notch quality"""
    log.trace('\x1b[G\x1b[?25l')
    for c in range(8):
        for line in _lines:
            log.trace(color(c % 8, line) + '\n')
            sleep(0.005)
        for _ in _lines:
            log.trace('\x1b[F')
    for line in _lines:
        log.trace(line + '\n')
    log.trace('\x1b[?25h')
