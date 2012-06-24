#!/usr/bin/env python

INCLUDE   = 'include'
TEMPLATES = 'templates'
CODEZ     = 'codez'

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

arch     = 'I386'
platform = 'LINUX'

import os, sys, subprocess, warnings, struct
from os.path import join, abspath, relpath, isfile, splitext

# Utility functions

from socket import htons, inet_aton, inet_ntoa, gethostbyname
def ip (host):
    return struct.unpack('I', inet_aton(gethostbyname(host)))[0]

from binascii import hexlify, unhexlify

# END of Utility functions

_GLUE, _TEMPLATE = range(2)
def glue(code):
    return [(_GLUE, (code, ))]

def template(templ, args = {}):
    return [(_TEMPLATE, (templ, args))]
