#!/usr/bin/env python
import sys
from time import sleep
from rainbow import rainbow

r0 = rainbow(3)
r1 = rainbow(10)
r2 = rainbow(10)
r3 = rainbow(15)
for i in range(10000):
    r0.pulsebar("3FPS PULSE")
    sys.stdout.write(" | ")
    r1.pulsebar("10FPS PULSE")
    sys.stdout.write(" | ")
    r2.scrollbar("SCROLLING BAR LENGTH 8", 8)
    sys.stdout.write(" | ")
    r3.scrollbar("HATERS GONNA HATE", 1)
    sys.stdout.flush()
    sleep(0.001)
    sys.stdout.write("\r")
