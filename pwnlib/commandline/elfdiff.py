#!/usr/bin/env python2
from argparse import ArgumentParser
from subprocess import CalledProcessError
from subprocess import check_output
from tempfile import NamedTemporaryFile


def dump(x):
    n = NamedTemporaryFile(delete=False)
    o = check_output(['objdump','-d','-x','-s',x])
    n.write(o)
    n.flush()
    return n.name

def diff(a,b):
    try: return check_output(['diff',a,b])
    except CalledProcessError as e:
        return e.output


p = ArgumentParser()
p.add_argument('a')
p.add_argument('b')

def main():
    a = p.parse_args()
    print diff(dump(a.a), dump(a.b))

if __name__ == '__main__': main()
