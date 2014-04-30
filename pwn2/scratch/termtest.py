import pwn2.nonlib.term
from pwn2.nonlib.term import *
import time, os, sys, threading

from pwn2.lib.log import *

try:
    # output(os.urandom(10))
    # print 'foo'
    # print 'bar'
    # h = output('')
    # for i in range(250):
    #     time.sleep(0.005)
    #     print 'foo%d' % i
    #     # print 'xx'
    #     # time.sleep(1)
    #     # update(h, 'hello \x1b[3%dmthere\x1b[m\n' % (i % 6 + 1))
    # # freeze(h)
    # # print pwn2.nonlib.term.parse('hello \x1b[32mthere\x1b[m\n')
    # # output('hello \x1b[32mthere\x1b[m\n')
    # # update(h, 'asdf')
    # print 'hello'

    # output('fooxxx')
    # h1 = output('')
    # h2 = output('bar')
    # output(' baz\n')

    # # update(h2, 'BAR')
    # update(h1, '\x1b[K\x1b[2A\x1b[1;31mYOLO\x1b[m\x1b[2B')

    # print 'fooxxx\x1b[2Dbar', 'baz'

    from pwn2.nonlib.stdin import readline

    clock = output(float = True)
    def loop():
        while True:
            clock.update('\n' + time.asctime(time.localtime()) + '\n')
            time.sleep(1)
    t = threading.Thread(target = loop)
    t.daemon = True
    t.start()
    i = 0
    # numlines = output()
    numlines = info(frozen = False)
    while True:
        s = ''
        numlines.update('You have written %d lines' % i)
        i += 1
        s = raw_input('> ')
        output('you wrote: ')
        output('%s\n' % s, indent = 20)
        if s == 'q':
            break

    # output('\xc3\xb8' * 85)
    # output('\x1b[44m \x1b[m')
    # # output('\x1b[J')
    # time.sleep(1)

    # h = output('last\n', float = True)
    # output('foo')
    # # update(h, 'LAST\n')
    # h = output('bar')
    # output('baz\n')
    # # delete(h)
    # update(h, 'BAR')


    # output('\x1b[s\x1b[20;40H')
    # h = output('yolo')
    # update(h, 'YOLO\x1b[u')

    # output('\n')
    # pwn2.nonlib.term.goto((1, 0))
    # pwn2.nonlib.term.put('%d' % pwn2.nonlib.term.scroll)
    # pwn2.nonlib.term.flush()
    # time.sleep(1)

    # pwn2.nonlib.term.put('\n'*10)

    pass

except:
    # pwn2.nonlib.term.fini()
    # raise e
    # pwn2.nonlib.term.put(str(e))
    pass
    raise

pwn2.nonlib.term.put('\n' * 20)
for c in pwn2.nonlib.term.cells:
    pwn2.nonlib.term.put('%s %s %s %s\n' % (c.start, c.end, c.float, `c.content`))
