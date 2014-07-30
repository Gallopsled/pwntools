import pwn

pwn.splash()
pwn.pause()

h = pwn.log.waitfor("Inputting:")

while True:
    l = raw_input('> ')
    h.status(l.upper())
