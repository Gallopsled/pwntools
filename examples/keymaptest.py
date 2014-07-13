import pwn

def match(t):
    print 'match', t

def nomatch(t):
    print 'nomatch', t

def key(t):
    print 'key', t

def tab(t):
    print 'tab', t

def tabtab(t):
    print 'tabtab', t

import pwnlib.term.keymap
km = pwnlib.term.keymap.Keymap({
    '<match>'     : match,
    '<nomatch>'   : nomatch,
    '<any>'       : key,
    '<tab>'       : tab,
    '<tab> <tab>' : tabtab,
    })

km.handle_input()
