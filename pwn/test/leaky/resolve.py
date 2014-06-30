#!/usr/bin/env python

import pwn
import sys
import subprocess
import re

def execute(cmd, args):
    ar = [cmd] + [str(a) for a in args]
    p = subprocess.Popen(ar, stdout = subprocess.PIPE)
    return p.stdout.read()[0:-1]

def pidof(cmd):
    return [int(n) for n in execute('pidof', [cmd]).split(' ')]

def symbol_offsets(elf):
    '''
    Returns a dictionary of symbols to their offsets inside the specified elf binary.
    '''
    offsets = {}
    for l in execute('readelf', ['-s', elf]).split('\n'):
        m = re.match('^\\s+\\d+: ([0-9a-f]+)\\s+(\\d+) FUNC    ((WEAK)|(GLOBAL))\\s+DEFAULT\\s+\\d+ (.*)$', l)
        if m and int(m.group(2)) > 0:
            offsets[m.group(6).split('@')[0]] = int(m.group(1), 16)
    return offsets

def mappings(pid):
    '''
    Returns mappings for the specified pid as tuples of two elements.
    First element is the full path to the binary, the second is the base address of the binary.
    '''
    mappings = []
    for l in open('/proc/%d/maps' % pid, 'r').read().split('\n'):
        m = re.match('^([0-9a-f]+)-([0-9a-f]+) ..xp [0-9a-f]+ ..:.. \\d+ \\s+ (/.*)$', l)
        if m:
            mappings.append((m.group(3), int(m.group(1), 16)))
    return mappings


def leaker(port):
    r = pwn.remote('localhost', port = port)
    d = r.recv(8)
    func = pwn.p32
    if len(d) == 8:
        func = pwn.p64
    def l(addr):
        r.send(pwn.flat(addr, func = func))
        d = r.recv(8)
        if d is None or len(d) == 0:
            raise 'Peer closed connection'
        return d
    return l

def find_module(modules, module):
    for m in modules:
        if module in m[0]:
            return m

def resolve_in_program_pid(program, pid, port):
    m = mappings(pid)
    main_module = find_module(m, program)
    leaky_module = find_module(m, 'libleaky')

    offsets = symbol_offsets(leaky_module[0])
    l = pwn.MemLeak(leaker(port))
    elf = pwn.DynELF(program, l, main_module[1])

    actual_address = offsets['find_me'] + leaky_module[1]
    resolved_address = elf.lookup('find_me', 'libleaky')
    formatter = pwn.text.green
    if not actual_address == resolved_address:
        formatter = pwn.text.red
    print
    print formatter('"find_me" is at 0x%x' % actual_address)
    print formatter('Resolver says "find_me" is at 0x%x' % resolved_address)



def resolve_in(program, port):
    pids = pidof(program)
    if len(pids) == 1:
        resolve_in_program_pid(program, pids[0], port)
    elif len(pids) == 0:
        print '%s is not running' % program
    else:
        print 'Too many instances of %s are running' % program

def main(args):
    if not len(args) == 3:
        print 'Usage: %s <program> <port>' % args[0]
    else:
        resolve_in(args[1], int(args[2]))
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
