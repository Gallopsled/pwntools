#!/usr/bin/env python

INCLUDE   = 'include'
TEMPLATES = 'templates'
CODEZ     = 'codez'

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

INTEL, MIPS = range(2)
arch = INTEL

import os, sys, subprocess, warnings, struct
from os.path import join, abspath, relpath, isfile, splitext

# Utility functions

from socket import htons, inet_aton, inet_ntoa, gethostbyname
def ip (host):
    return struct.unpack('I', inet_aton(gethostbyname(host)))[0]

from binascii import hexlify, unhexlify

# END of Utility functions

_GLUE, _TEMPLATE = range(2)

def asm32 (code):
    return [(_GLUE, (code, 32))]

def asm64 (code):
    return [(_GLUE, (code, 64))]

def asm (code):
    return asm32(code)

def template(templ, args = {}):
    return [(_TEMPLATE, (templ, args))]

