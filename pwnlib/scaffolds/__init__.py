#!/usr/bin/env python2
import sys

# Todo: Prettify
def question(line, default):
    sys.stdout.write("%s: " % line)
    answer = sys.stdin.readline().rstrip()
    sys.stdout.flush()

    if len(answer) < 1:
        return default

    return answer
